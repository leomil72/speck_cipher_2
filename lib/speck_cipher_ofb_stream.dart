/*

    IMPLEMENTATION OF SPECK64/128 CIPHER IN DART PROGRAMMING LANGUAGE

    Key features of the algorithm:
    block size: 64-bits (in 2 32-bits words)
    key size: 128-bits (in 4 32-bits words)
    Nr. of rounds: 27
    Word size: 32-bits

    OFB cipher mode of operation
    This version manages files as streams

*/
import 'dart:io';
import 'dart:math';

///class SpeckCipher
class SpeckCipher {
  static const blockSize = 64;
  static const keySize = 128;
  static const rounds = 27;
  static const wordSizeN = 32;
  static const keyWordsM = 4;

  SpeckCipher() {}

  ///Encryption function: gets a filename and a key
  Future<int> encryptFile(String fileName, List<int> k) async {
    List<int> Ct = [0, 0];
    List<int> rk = List<int>.filled(27, 0);
    //will contain file contents (plain text) in int32
    List<int> Pt = [0, 0];

    ///convert key into round key buffer of int32
    List<int> K = List<int>.filled(k.length ~/ 4, 0);
    bytesToWord32(k, K);
    //prepare key round
    keySchedule(K, rk);

    //check if input file exists
    final myInputFile = File(fileName);
    if (await myInputFile.exists() == false) {
      return -1;
    }

    //prepare output file
    final outputFile = await File(fileName + '.enc');
    var fileOutput = await outputFile.openWrite(mode: FileMode.write);
    //create and store IV (initialization vector)
    List<int> intVect = [0, 0];
    List<int> bytes = [0, 0, 0, 0, 0, 0, 0, 0];
    intVect[0] = IV();
    intVect[1] = IV();
    word32ToBytes(intVect, bytes);
    fileOutput.add(bytes);

    //open input file
    File fileInput = File(fileName);
    //read 8 bytes at a time
    int blockSize = 8;
    //for padding
    int padding = -1;
    //set input file to be read asynch
    var fileBytes = List<int>.from(await fileInput.readAsBytes());
    for (int i = 0; i < fileBytes.length; i += blockSize) {
      //check end of file
      int endIndex = i + blockSize;
      endIndex = endIndex > fileBytes.length ? fileBytes.length : endIndex;
      //read a block of 8 bytes
      List<int> block = fileBytes.sublist(i, endIndex);
      //check if pad if necessary
      if (endIndex == fileBytes.length) {
        padding = 8 - (endIndex % 8);
        //do padding if file lenght is not a mul of 8
        if (padding != 8) {
          for (int i = 0; i < padding; i++) {
            block.add(padding);
          }
        }
      }
      //encrypt and store current block
      bytesToWord32(block, Pt);
      encrypt(Pt, Ct, rk, intVect);
      word32ToBytes(Ct, block);
      fileOutput.add(block);
    }
    //if file lenght is a mul of 8, add another block
    if (padding == 8) {
      List<int> block = [8, 8, 8, 8, 8, 8, 8, 8];
      bytesToWord32(block, Pt);
      encrypt(Pt, Ct, rk, intVect);
      word32ToBytes(Ct, block);
      fileOutput.add(block);
    }
    //close output file
    await fileOutput.flush();
    await fileOutput.close();
    return 0;
  }

  ///decryption function: gets a filename and a key
  Future<int> decryptFile(String fileName, List<int> k) async {
    List<int> Ct = [0, 0];
    List<int> rk = List<int>.filled(27, 0);
    //convert file contents (plain text) in int32
    List<int> Pt = [0, 0];

    ///convert key into round key buffer of int32
    List<int> K = List<int>.filled(k.length ~/ 4, 0);
    bytesToWord32(k, K);
    //prepare key round
    keySchedule(K, rk);

    //check if input file exists
    final myInputFile = File(fileName + '.enc');
    if (await myInputFile.exists() == false) {
      return -1;
    }

    //prepare output file
    final outputFile = await File(fileName + '.dec');
    var fileOutput = await outputFile.openWrite(mode: FileMode.write);
    //create variables for IV (initialization vector)
    List<int> intVect = [0, 0];

    //open input file
    File fileInput = File(fileName + '.enc');
    //read 8 bytes at a time
    int blockSize = 8;
    //set input file to be read asynch
    var fileBytes = List<int>.from(await fileInput.readAsBytes());
    int i = 0;
    for (i = 0; i < fileBytes.length; i += blockSize) {
      //check end of file
      int endIndex = i + blockSize;
      endIndex = endIndex > fileBytes.length ? fileBytes.length : endIndex;
      //read a block of 8 bytes
      List<int> block = fileBytes.sublist(i, endIndex);
      if (i == 0) {
        //the first block contains the IV...
        bytesToWord32(block, intVect);
      } else {
        //...while the other ones the normal data...
        bytesToWord32(block, Ct);
        decrypt(Pt, Ct, rk, intVect);
        word32ToBytes(Pt, block);
        //...except for the last one, that is padded
        if (endIndex == fileBytes.length) {
          //get the lenght of padding
          int a = block[7];
          //remove the extra bytes and write the remaining data
          while (a > 0) {
            block.removeLast();
            a--;
          }
        }
        /*if (block.isNotEmpty)*/ fileOutput.add(block);
      }
    }
    //close output file
    await fileOutput.flush();
    await fileOutput.close();
    return 0;
  }

  ///32-bits right rotation function
  int Ror(int x, int r) {
    int tmp = (x << (wordSizeN - r)) & 0x00000000ffffffff;
    return (((x >> r) | tmp) & 0x00000000ffffffff);
  }

  ///32-bits left rotation function
  int Rol(int x, int r) {
    int tmp = (x >> (wordSizeN - r)) & 0x00000000ffffffff;
    return (((x << r) | tmp) & 0x00000000ffffffff);
  }

  ///initialization vector: returns a 32-bits integer
  int IV() {
    int rnd = 0;
    try {
      rnd = Random.secure().nextInt(1 << 32);
    } catch (e) {
      rnd = Random().nextInt(1 << 32);
    }
    return rnd;
  }

  ///convert 4 bytes into a single 32-bits word using little-endian order:
  ///first byte into the right-most 8-bits, and so on up to the left
  void bytesToWord32(List<int> bytes, List<int> words) {
    int numBytes = bytes.length;
    int j = 0;
    for (int i = 0; i < numBytes / 4; i++) {
      words[i] = bytes[j] |
          ((bytes[j + 1] << 8)) |
          ((bytes[j + 2] << 16)) |
          ((bytes[j + 3] << 24));
      j += 4;
    }
  }

  ///revert a 32-bits word into 4 bytes using little-endian order:
  ///right-most 8-bits into the first byte, and so on up to the left
  void word32ToBytes(List<int> words, List<int> bytes) {
    int numWords = words.length;
    int j = 0;
    for (int i = 0; i < numWords; i++) {
      bytes[j] = words[i] & 0xff;
      bytes[j + 1] = (words[i] >> 8) & 0xff;
      bytes[j + 2] = (words[i] >> 16) & 0xff;
      bytes[j + 3] = (words[i] >> 24) & 0xff;
      j += 4;
    }
  }

  ///key scheduler: gets a key and prepare a round key buffer
  void keySchedule(List<int> key, List<int> subKey) {
    int D = key[3];
    int C = key[2];
    int B = key[1];
    int A = key[0];

    for (int i = 0; i < rounds;) {
      subKey[i] = A;
      B = Ror(B, 8);
      B = (B + A) & 0x00000000ffffffff;
      B ^= i++;
      A = Rol(A, 3);
      A ^= B;

      subKey[i] = A;
      C = Ror(C, 8);
      C = (C + A) & 0x00000000ffffffff;
      C ^= i++;
      A = Rol(A, 3);
      A ^= C;

      subKey[i] = A;
      D = Ror(D, 8);
      D = (D + A) & 0x00000000ffffffff;
      D ^= i++;
      A = Rol(A, 3);
      A ^= D;
    }
  }

  ///encrypt a block using the round key and the IV, and returns a crypted block
  void encrypt(List<int> Pt, List<int> Ct, List<int> rk, List<int> intVect) {
    for (int i = 0; i < rounds;) {
      intVect[1] = Ror(intVect[1], 8);
      intVect[1] = (intVect[1] + intVect[0]) & 0x00000000ffffffff;
      intVect[1] ^= rk[i++];
      intVect[0] = Rol(intVect[0], 3);
      intVect[0] ^= intVect[1];
    }
    Ct[0] = Pt[0] ^ intVect[0];
    Ct[1] = Pt[1] ^ intVect[1];
  }

  ///decrypt a block using the round key and the IV, and returns a decrypted block
  void decrypt(List<int> Pt, List<int> Ct, List<int> rk, List<int> intVect) {
    for (int i = 0; i < rounds;) {
      intVect[1] = Ror(intVect[1], 8);
      intVect[1] = (intVect[1] + intVect[0]) & 0x00000000ffffffff;
      intVect[1] ^= rk[i++];
      intVect[0] = Rol(intVect[0], 3);
      intVect[0] ^= intVect[1];
    }
    Pt[0] = Ct[0] ^ intVect[0];
    Pt[1] = Ct[1] ^ intVect[1];
  }
}
