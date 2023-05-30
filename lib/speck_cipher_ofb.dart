/*

    IMPLEMENTATION OF SPECK64/128 CIPHER IN DART PROGRAMMING LANGUAGE

    Key features of the algorithm:
    block size: 64-bits (in 2 32-bits words)
    key size: 128-bits (in 4 32-bits words)
    Nr. of rounds: 27
    Word size: 32-bits


*/
import 'dart:io';
import 'dart:math';

class SpeckCipher {
  static const blockSize = 64;
  static const keySize = 128;
  static const rounds = 27;
  static const wordSizeN = 32;
  static const keyWordsM = 4;

  SpeckCipher() {}

  // ***************************************************
  Future<int> encryptFile(String fileName, List<int> k) async {
    List<int> Ct = [0, 0];
    List<int> rk = List<int>.filled(27, 0);
    //convert file contents (plain text) in int32
    List<int> Pt = [0, 0];

    ///convert key into round key buffer of int32
    List<int> K = List<int>.filled(k.length ~/ 4, 0);
    bytesToWord32(k, K);
    //prepare key round
    keySchedule(K, rk);

    //read file as a bytes array
    final myInputFile = await File(fileName);
    if (await myInputFile.exists() == false) {
      return -1;
    }
    var fileLength = await myInputFile.length();
    var pt = List<int>.from(await myInputFile.readAsBytes());
    //padding input file with 0s
    if (fileLength % 8 != 0) {
      for (int i = 0; i < (8 - fileLength % 8); i++) {
        pt.add(0);
      }
    }

    //open file to store encrypted data
    final myFile = await File(fileName + '.enc');
    var fileStream = await myFile.openWrite(mode: FileMode.write);
    //create and store IV (initialization vector)
    List<int> intVect = [0, 0];
    List<int> bytes = [0, 0, 0, 0, 0, 0, 0, 0];
    intVect[0] = IV();
    intVect[1] = IV();
    word32ToBytes(intVect, bytes);
    fileStream.add(bytes);
    //start encryption
    for (int i = 0; i < pt.length ~/ 8; i++) {
      //convert plain text into array of int32
      var bytes = <int>[];
      for (int k = 0; k < 2; k++) {
        for (int j = 0; j < 4; j++) {
          bytes.add(pt[(i * 8) + (k * 4) + j]);
        }
      }
      bytesToWord32(bytes, Pt);
      encrypt(Pt, Ct, rk, intVect);
      word32ToBytes(Ct, bytes);
      fileStream.add(bytes);
    }
    await fileStream.flush();
    await fileStream.close();
    return 0;
  }

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

    //read file as a bytes array
    final myInputFile = await File(fileName + '.enc');
    if (await myInputFile.exists() == false) {
      return -1;
    }
    var fileLength = await myInputFile.length();
    var ct = List<int>.from(await myInputFile.readAsBytes());
    //padding input file with 0s
    if (fileLength % 8 != 0) {
      for (int i = 0; i < (8 - fileLength % 8); i++) {
        ct.add(0);
      }
    }

    List<int> intVect = [0, 0];
    //open file to store plain data
    final myFile = File(fileName + '.dec');
    var fileStream = myFile.openWrite(mode: FileMode.write);
    //start encryption
    for (int i = 0; i < ct.length ~/ 8; i++) {
      //convert plain text into array of int32
      var bytes = <int>[];
      for (int k = 0; k < 2; k++) {
        for (int j = 0; j < 4; j++) {
          bytes.add(ct[(i * 8) + (k * 4) + j]);
        }
      }
      if (i == 0) {
        bytesToWord32(bytes, intVect);
      } else {
        bytesToWord32(bytes, Ct);
        decrypt(Pt, Ct, rk, intVect);
        word32ToBytes(Pt, bytes);
        fileStream.add(bytes);
      }
    }
    await fileStream.flush();
    await fileStream.close();
    return 0;
  }

  //32-bits right rotation function
  int Ror(int x, int r) {
    int tmp = (x << (wordSizeN - r)) & 0x00000000ffffffff;
    return (((x >> r) | tmp) & 0x00000000ffffffff);
  }

  //32-bits left rotation function
  int Rol(int x, int r) {
    int tmp = (x >> (wordSizeN - r)) & 0x00000000ffffffff;
    return (((x << r) | tmp) & 0x00000000ffffffff);
  }

  //initialization vector
  int IV() {
    int rnd = 0;
    try {
      rnd = Random.secure().nextInt(1 << 32);
    } catch (e) {
      rnd = Random().nextInt(1 << 32);
    }
    return rnd;
  }

  //convert 4 bytes into a single 32-bits word using little-endian order:
  //first byte into the right-most 8-bits, and so on up to the left
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

  //revert a 32-bits word into 4 bytes using little-endian order:
  //right-most 8-bits into the first byte, and so on up to the left
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
