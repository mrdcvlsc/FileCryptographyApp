#include <jni.h>
#include <iostream>
#include <thread>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <random>
#include <chrono>
#include <limits>
#include "Krypt/src/Krypt.hpp"
#include "jpp.hpp"

using namespace Krypt;
using namespace Jpp;

extern "C" JNIEXPORT jstring JNICALL Java_com_application_bethela_BethelaActivity_doubleString (
  JNIEnv *env,
  jobject,
  jstring arg
) {
  jboolean isCopy = 1;
  const char *c_str_arg = env->GetStringUTFChars(arg, &isCopy);
  std::string test(c_str_arg);
  test += " | 2" + test + " : ";
  jstring doubleString = env->NewStringUTF(test.c_str());
  delete[] c_str_arg;
  return doubleString;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_application_bethela_BethelaActivity_doubleByte (
  JNIEnv *env,
  jobject,
  jbyteArray arg,
  jint size
) {
  const jbyte *read_only = env->GetByteArrayElements(arg, nullptr);

  jbyteArray doubleArray = env->NewByteArray(size * 2);
  env->SetByteArrayRegion(doubleArray, 0, size, read_only);
  env->SetByteArrayRegion(doubleArray, size, size, read_only);

  return doubleArray;
}

extern "C" JNIEXPORT jobjectArray JNICALL Java_com_application_bethela_BethelaActivity_transpose (
  JNIEnv *env,
  jobject,
  jobjectArray arr,
  jint row,
  jint column
) {
  // Create a vector that will hold the original jintArray rows
  std::vector<jintArray> original_rows;

  // Allocate an array of pointers that will contain the copy/reference of the rows
  jint **row_elements = new jint *[row];

  for (jsize i = 0; i < row; ++i) {
    // get the `jintArray` row at index `i` of the `jobjectArray arr`, push it to a vector
    original_rows.push_back((jintArray) env->GetObjectArrayElement(arr, i));

    // create a copy/reference buffer of the aquired `jintArray`
    row_elements[i] = env->GetIntArrayElements(original_rows.back(), nullptr);
  }

  // Allocate a new C 2D array for the transpose and apply the transpose
  jint **transposed_row_elements = new jint *[column];
  for (jsize i = 0; i < column; ++i) {
    transposed_row_elements[i] = new jint[row];
    for (jsize j = 0; j < row; ++j) {
      transposed_row_elements[i][j] = row_elements[j][i];
    }
  }

  // create a new jobjectArray that will contain the transpose 2D array values
  jclass jintArrayClass = env->FindClass("[I");
  jobjectArray transposed = env->NewObjectArray(column, jintArrayClass, nullptr);

  for (jsize i = 0; i < column; ++i) {
    // create a new jintArray
    jintArray curr_row = env->NewIntArray(row);

    // set the values of the new jintArray using the values of the transposed matrix
    env->SetIntArrayRegion(curr_row, 0, row, transposed_row_elements[i]);

    // add the row jintArray to the main jobjectArray transpose matrix
    env->SetObjectArrayElement(transposed, i, curr_row);
  }

  // release the copy/reference buffers of the original rows that we got from the first loop
  for (jsize i = 0; i < row; ++i) {
    env->ReleaseIntArrayElements(original_rows[i], row_elements[i], 0);
  }

  // deallocate all of the C++ array that we allocated using C++ convention
  for (jsize i = 0; i < column; ++i) {
    delete[] transposed_row_elements[i];
  }

  delete[] transposed_row_elements;
  delete[] row_elements;

  return transposed;
}

extern "C" JNIEXPORT jintArray JNICALL Java_com_application_bethela_BethelaActivity_reverse (
  JNIEnv *env,
  jobject,
  jintArray arr,
  jint size
) {
  // A C array that could be a copy or a direct pointer to `arr`
  jint *reverse_array = env->GetIntArrayElements(arr, nullptr);

  // reverse the array
  for (jsize i = 0; i < size / 2; ++i) {
    jint temp = reverse_array[i];
    reverse_array[i] = reverse_array[size - 1 - i];
    reverse_array[size - 1 - i] = temp;
  }

  // free the C array and apply the changes back to the `arr`
  env->ReleaseIntArrayElements(arr, reverse_array, 0);

  return arr;
}

/// equivalent to : `this.getApplicationContext().getContentResolver().openInputStream(Uri);`
jobject openFileUriInputStream (JNIEnv *env, jobject thiz, jobject uri) {
  return Activity(env, thiz).
    getApplicationContext().
    getContentResolver().
    openInputStream(Uri(env, uri)).
    _thiz;
}

jstring getFileName (JNIEnv *env, jobject thiz, jobject file_uri) {
  Uri fileUri(env, file_uri);
  Cursor c = Activity(env, thiz).
    getApplicationContext().
    getContentResolver().
    query(fileUri, nullptr, nullptr, nullptr, nullptr);

  c.moveToFirst();

  jstring DISPLAY_NAME = env->NewStringUTF("_display_name");
  jstring fileName = c.getString(c.getColumnIndexOrThrow(DISPLAY_NAME));
  c.close();
  return fileName;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_application_bethela_BethelaActivity_getFileNameNative (
  JNIEnv *env,
  jobject thiz,
  jobject file_uri
) {
  return getFileName(env, thiz, file_uri);
}

extern "C" JNIEXPORT jint JNICALL Java_com_application_bethela_BethelaActivity_encryptFiles (
  JNIEnv *env, jobject thiz,
  jbyteArray key_file,
  jobject target_files,
  jobject output_path
) {
  ArrayList<Uri> file_queue(env, target_files);

  jbyte *aeskey = env->GetByteArrayElements(key_file, nullptr);
  jint aeskey_size = env->GetArrayLength(key_file);

  Mode::CBC<BlockCipher::AES, Padding::PKCS_5_7> aes_scheme(
    reinterpret_cast<Bytes *>(aeskey),
    aeskey_size
  );

  std::atomic<size_t> cnt(0);
  std::mutex vector_mtx;

  constexpr jsize bufferSize = 1 * 1024 * 1024;
  if (bufferSize % 16 != 0 || bufferSize <= 16) {
    return 0xffffffff; // invalid buffer size
  }

  auto encrypt_lambda = [&] () -> void {
    bool run_thread = true;

    Bytes *encryptedBuffer = new Bytes[bufferSize];

    while (run_thread) {
      try {
        std::string target_file;
        Uri target_uri(env, NULL);

        vector_mtx.lock();
        run_thread = !file_queue.isEmpty();

        if (run_thread) {
          target_uri._thiz = file_queue.remove(file_queue.size() - 1)._thiz;
          jstring filename = getFileName(env, thiz, target_uri._thiz);
          const char *c_filename_buffer = env->GetStringUTFChars(filename, NULL);
          target_file = std::string(c_filename_buffer);
          env->ReleaseStringUTFChars(filename, c_filename_buffer);
        } else {
          vector_mtx.unlock();
          break;
        }

        vector_mtx.unlock();

        InputStream incoming_bytes = InputStream(
          env,
          openFileUriInputStream(env, thiz, target_uri._thiz)
        );

        std::string outfname(target_file + ".bthl");
        jstring jniOutputFileName = env->NewStringUTF(outfname.c_str());

        jstring mimeType = env->NewStringUTF("application/octet-stream");
        DocumentFile folder = DocumentFile::fromTreeUri(
          env,
          Activity(env, thiz).getApplicationContext(),
          Uri(env, output_path)
        );

        DocumentFile outputFile = folder.createFile(mimeType, jniOutputFileName);

        OutputStream outgoing_bytes = Activity(env, thiz).getApplicationContext().getContentResolver().openOutputStream(outputFile.getUri());

        constexpr jint fileSignatureSize = 7;
        jbyteArray fileSignature = env->NewByteArray(fileSignatureSize);
        const jbyte fileSig[fileSignatureSize] = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
        env->SetByteArrayRegion(fileSignature, 0, fileSignatureSize, fileSig);
        outgoing_bytes.write(fileSignature, 0, fileSignatureSize);

        constexpr jint AES_BLOCK = 16;
        jint length;
        jbyteArray jniBuffer = env->NewByteArray(bufferSize);

        // generate random IV
        unsigned char iv[AES_BLOCK];

        unsigned seed = std::chrono::steady_clock::now().time_since_epoch().count();
        std::mt19937 rand_engine(seed);
        std::uniform_int_distribution<int> random_number(
          std::numeric_limits<int>::min(),
          std::numeric_limits<int>::max()
        );

        for(size_t i = 0; i < AES_BLOCK; ++i) {
          iv[i] = random_number(rand_engine);
        }

        jbyteArray jniIV = env->NewByteArray(AES_BLOCK);
        env->SetByteArrayRegion(jniIV, 0, AES_BLOCK, reinterpret_cast<jbyte *>(iv));
        outgoing_bytes.write(jniIV, 0, AES_BLOCK);

        while ((length = incoming_bytes.read(jniBuffer)) > 0) {
          jbyte *buffer = (jbyte *) env->GetPrimitiveArrayCritical(jniBuffer, NULL);

          if (length == bufferSize) {
            for (size_t index = 0; index < length; index += AES_BLOCK) {
              aes_scheme.blockEncrypt(
                reinterpret_cast<unsigned char *>(buffer + index),
                reinterpret_cast<unsigned char *>(encryptedBuffer + index),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            env->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            env->SetByteArrayRegion(
              jniBuffer, 0, length,
              reinterpret_cast<jbyte *>(encryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, length);
          } else {
            size_t remaining_blocks = length / AES_BLOCK;
            size_t index;

            for (index = 0; index < remaining_blocks - 1; ++index) {
              aes_scheme.blockEncrypt(
                reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK)),
                reinterpret_cast<unsigned char *>(encryptedBuffer + (index * AES_BLOCK)),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            env->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            env->SetByteArrayRegion(
              jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK,
              reinterpret_cast<jbyte *>(encryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK);

            ByteArray recover = aes_scheme.encrypt(
              reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK)),
              AES_BLOCK, reinterpret_cast<unsigned char *>(iv)
            );

            env->SetByteArrayRegion(
              jniBuffer, 0, recover.length,
              reinterpret_cast<jbyte *>(recover.array));
            outgoing_bytes.write(jniBuffer, 0, recover.length);
          }
        }

        if (env->ExceptionCheck()) {
          env->ExceptionDescribe();
          outgoing_bytes.close();
          outputFile.Delete();
        } else {
          cnt++;
        }
      } catch (...) {
        continue;
      }
    }

    delete[] encryptedBuffer;
  };

  // TODO: implement multi-threading
  encrypt_lambda();

  return cnt.load(std::memory_order_relaxed);
}

extern "C" JNIEXPORT jint JNICALL Java_com_application_bethela_BethelaActivity_decryptFiles (
  JNIEnv *env, jobject thiz,
  jbyteArray key_file,
  jobject target_files,
  jobject output_path
) {
  ArrayList<Uri> file_queue(env, target_files);

  jbyte *aeskey = env->GetByteArrayElements(key_file, nullptr);
  jint aeskey_size = env->GetArrayLength(key_file);

  Mode::CBC<BlockCipher::AES, Padding::PKCS_5_7> aes_scheme(
    reinterpret_cast<Bytes *>(aeskey),
    aeskey_size
  );

  std::atomic<size_t> cnt(0);
  std::mutex vector_mtx;

  constexpr jsize bufferSize = 1 * 1024 * 1024;
  if (bufferSize % 16 != 0 || bufferSize <= 16) {
    return 0xffffffff; // invalid buffer size
  }

  auto decrypt_lambda = [&] () -> void {
    bool run_thread = true;

    Bytes *decryptedBuffer = new Bytes[bufferSize];

    while (run_thread) {
      try {
        std::string target_file;
        Uri target_uri(env, NULL);

        vector_mtx.lock();
        run_thread = !file_queue.isEmpty();

        if (run_thread) {
          target_uri._thiz = file_queue.remove(file_queue.size() - 1)._thiz;
          jstring filename = getFileName(env, thiz, target_uri._thiz);
          const char *c_filename_buffer = env->GetStringUTFChars(filename, NULL);
          target_file = std::string(c_filename_buffer);
          env->ReleaseStringUTFChars(filename, c_filename_buffer);
        } else {
          vector_mtx.unlock();
          break;
        }

        vector_mtx.unlock();

        InputStream incoming_bytes = InputStream(
          env,
          openFileUriInputStream(env, thiz, target_uri._thiz)
        );

        std::string outfname(target_file);
        std::string fileExtension = "";

        constexpr size_t filename_extension_size = 5;
        if (outfname.size() > filename_extension_size) {
          fileExtension = outfname.substr(outfname.size() - filename_extension_size, filename_extension_size);
        }

        outfname = outfname.substr(0, outfname.size() - filename_extension_size);

        jstring jniOutputFileName = env->NewStringUTF(outfname.c_str());

        jstring mimeType = env->NewStringUTF("application/octet-stream");
        DocumentFile folder = DocumentFile::fromTreeUri(
          env,
          Activity(env, thiz).getApplicationContext(),
          Uri(env, output_path)
        );

        DocumentFile outputFile = folder.createFile(mimeType, jniOutputFileName);

        OutputStream outgoing_bytes = Activity(env, thiz).getApplicationContext().getContentResolver().openOutputStream(outputFile.getUri());

        constexpr jint fileSignatureSize = 7;
        jbyteArray fileSignature = env->NewByteArray(fileSignatureSize);
        incoming_bytes.read(fileSignature);

        const jbyte fileSig[fileSignatureSize] = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
        jbyte *fileSigRead = env->GetByteArrayElements(fileSignature, NULL);

        constexpr jint AES_BLOCK = 16;
        jint length;
        jbyteArray jniBuffer = env->NewByteArray(bufferSize);
        jbyteArray jniIV = env->NewByteArray(AES_BLOCK);
        incoming_bytes.read(jniIV);
        jbyte *iv = env->GetByteArrayElements(jniIV, NULL);

        std::string properFileExtension = ".bthl";

        jboolean signFailed = std::memcmp(fileSigRead, fileSig, fileSignatureSize);
        jboolean wrongFileExtension = fileExtension != properFileExtension;
        jboolean JNIException = env->ExceptionCheck();

        env->ReleaseByteArrayElements(fileSignature, fileSigRead, 0);

        if (JNIException) {
          env->ExceptionDescribe();
        }

        if (signFailed || wrongFileExtension || JNIException) {
          outgoing_bytes.close();
          outputFile.Delete();
          continue;
        }

        while ((length = incoming_bytes.read(jniBuffer)) > 0) {
          jbyte *buffer = (jbyte *) env->GetPrimitiveArrayCritical(jniBuffer, NULL);

          if (length == bufferSize) {
            for (size_t index = 0; index < length; index += AES_BLOCK) {
              aes_scheme.blockDecrypt(
                reinterpret_cast<unsigned char *>(buffer + index),
                reinterpret_cast<unsigned char *>(decryptedBuffer + index),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            env->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            env->SetByteArrayRegion(
              jniBuffer, 0, length,
              reinterpret_cast<jbyte *>(decryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, length);
          } else {
            size_t remaining_blocks = length / AES_BLOCK;
            size_t index;

            for (index = 0; index < remaining_blocks - 1; ++index) {
              aes_scheme.blockDecrypt(
                reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK)),
                reinterpret_cast<unsigned char *>(decryptedBuffer + (index * AES_BLOCK)),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            env->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            env->SetByteArrayRegion(
              jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK,
              reinterpret_cast<jbyte *>(decryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK);

            ByteArray recover = aes_scheme.decrypt(
              reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK)),
              AES_BLOCK, reinterpret_cast<unsigned char *>(iv)
            );

            env->SetByteArrayRegion(
              jniBuffer, 0, recover.length,
              reinterpret_cast<jbyte *>(recover.array));
            outgoing_bytes.write(jniBuffer, 0, recover.length);
          }
        }

        env->ReleaseByteArrayElements(jniIV, iv, 0);

        if (env->ExceptionCheck()) {
          env->ExceptionDescribe();
          outgoing_bytes.close();
          outputFile.Delete();
        } else {
          cnt++;
        }
      } catch (...) {
        continue;
      }
    }

    delete[] decryptedBuffer;
  };

  // TODO: implement multi-threading
  decrypt_lambda();

  return cnt.load(std::memory_order_relaxed);
}