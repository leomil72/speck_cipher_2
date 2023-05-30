/*

  IMPLEMENTATION OF SPECK64/128 CIPHER IN DART PROGRAMMING LANGUAGE

  Main code
  
*/

import 'dart:convert';
import 'dart:io';

import 'package:speck_cipher/speck_cipher_ofb_stream.dart';

SpeckCipher speckCipher = new SpeckCipher();

void main(List<String> arguments) async {
  //open input file - if it doens't exist, create it
  final myFile = File('plainfile.txt');
  if (!await myFile.exists()) {
    var fileOut = myFile.openWrite(mode: FileMode.write);
    fileOut.write('sample text');
    await fileOut.flush();
    await fileOut.close();
  }

  // main
  print('SPECK64/128 CIPHER');
  // ask for key
  stdout.write('Enter password (16 chars, no spaces): ');
  var tmpKey = stdin.readLineSync(encoding: utf8) ?? '';
  tmpKey = tmpKey.replaceAll(' ', '');
  if (tmpKey.isEmpty) {
    return;
  }
  //convert key into list of bytes and adjust to 16 bytes wide
  var k = List<int>.from(utf8.encode(tmpKey));
  while (k.length < 16) {
    k.add(0);
  }
  while (k.length > 16) {
    k.removeLast();
  }

  // ask for file input
  stdout.write('\nEnter name of file to be encrypted: ');
  var fileName = (stdin.readLineSync(encoding: utf8) ?? '').trim();
  if (fileName.isEmpty) {
    return;
  }
  // encrypting
  stdout.write('\nOpening $fileName and starting encryption... ');
  var tmp = await speckCipher.encryptFile(fileName, k);
  if (tmp == -1) {
    stdout.write('Input file not found. Aborted.\n');
    return;
  }
  // decrypting
  stdout.write('File encrypted\nNow decrypting... ');
  tmp = await speckCipher.decryptFile(fileName, k);
  if (tmp == -1) {
    stdout.write('Encrypted file not found. Aborted.\n');
  }
  stdout.write('File decrypted.\nProcess correctly terminated\n');
}
