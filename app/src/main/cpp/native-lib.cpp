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
#include <android/log.h>

#define USE_ARM_AES

#include "Krypt/src/Krypt.hpp"
#include "jpp.hpp"

using namespace Krypt;
using namespace Jpp;

constexpr static jsize MB = 1;

/// release buffer size.
constexpr static jsize BUFFER_SIZE = MB * 1024 * 1024;

/// debug buffer size.
//constexpr static jsize BUFFER_SIZE = 32;

/// 5 characters.
constexpr static size_t FILE_EXTENSION_SIZE = 5;

/// 7 byte file signature.
constexpr static jint FILE_SIGNATURE_SIZE = 7;

/// the size of one AES block in bytes.
constexpr static size_t AES_BLOCK_SIZE = 16;

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
  jbyte *read_only = env->GetByteArrayElements(arg, nullptr);

  jbyteArray doubleArray = env->NewByteArray(size * 2);
  env->SetByteArrayRegion(doubleArray, 0, size, read_only);
  env->SetByteArrayRegion(doubleArray, size, size, read_only);

  env->ReleaseByteArrayElements(arg, read_only, 0);

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

namespace RESULT_CODE {
  jint INVALID_INTERNAL_BUFFER_SIZE = -1;
  jint THREAD_ATTACHMENT_FAILED = -2;
  jint FILE_ERROR = -3;
}

/// equivalent to : `this.getApplicationContext().getContentResolver().openInputStream(Uri);`
jobject openFileUriInputStream (JNIEnv *env, jobject thiz, jobject uri) {
  return Activity(env, thiz)
    .getApplicationContext()
    .getContentResolver()
    .openInputStream(Uri(env, uri))
    ._thiz;
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

  env->ReleaseByteArrayElements(key_file, aeskey, 0);

  std::atomic<jint> cnt(0);
  std::mutex vector_mtx;

  if (BUFFER_SIZE % AES_BLOCK_SIZE != 0 || BUFFER_SIZE <= AES_BLOCK_SIZE) {
    return RESULT_CODE::INVALID_INTERNAL_BUFFER_SIZE;
  }

  JavaVM* javaVM;
  env->GetJavaVM((_JavaVM**) &javaVM);
  jobject DocumentFileClass = env->NewGlobalRef((jobject) env->FindClass("androidx/documentfile/provider/DocumentFile"));
  jobject globalThis = env->NewGlobalRef(thiz);
  jobject globalOutputPath = env->NewGlobalRef(output_path);

  auto encrypt_lambda = [&] () -> void {
    JNIEnv* threadEnv;

    jint isDifferentThread = javaVM->GetEnv((void **) &threadEnv, JNI_VERSION_1_6);

    if (isDifferentThread == JNI_EDETACHED) {
      javaVM->AttachCurrentThread((_JNIEnv**) &threadEnv, NULL);
    } else if (isDifferentThread == JNI_OK) {
      threadEnv = env;
    } else {
      __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption ", "thread attachment failed");
      return;
    }

    bool run_thread = true;

    Bytes *encryptedBuffer = new Bytes[BUFFER_SIZE];

    std::string target_file;

    while (run_thread) {
      try {
        Uri target_uri(threadEnv);

        vector_mtx.lock();
        run_thread = !file_queue.isEmpty(threadEnv);

        if (run_thread) {
          target_uri._thiz = file_queue.remove(threadEnv, file_queue.size(threadEnv) - 1)._thiz;
          target_uri._Jclass = threadEnv->GetObjectClass(target_uri._thiz);
          jstring filename = getFileName(threadEnv, globalThis, target_uri._thiz);
          const char *c_filename_buffer = threadEnv->GetStringUTFChars(filename, NULL);
          target_file = std::string(c_filename_buffer);
          threadEnv->ReleaseStringUTFChars(filename, c_filename_buffer);
        } else {
          vector_mtx.unlock();
          break;
        }

        vector_mtx.unlock();

        InputStream incoming_bytes = InputStream(
          threadEnv,
          openFileUriInputStream(threadEnv, globalThis, target_uri._thiz)
        );

        std::string outfname(target_file + ".bthl");
        jstring jniOutputFileName = threadEnv->NewStringUTF(outfname.c_str());

        jstring mimeType = threadEnv->NewStringUTF("application/octet-stream");

        Uri treeUri(threadEnv, globalOutputPath);
        Context folder_ctx = Activity(threadEnv, globalThis).getApplicationContext();

        DocumentFile folder = DocumentFile::fromTreeUri(
          threadEnv,
          folder_ctx,
          treeUri,
          (jclass) DocumentFileClass
        );

        DocumentFile outputFile = folder.createFile(mimeType, jniOutputFileName);

        OutputStream outgoing_bytes = Activity(threadEnv, globalThis).getApplicationContext().getContentResolver().openOutputStream(outputFile.getUri());

        jbyteArray fileSignature = threadEnv->NewByteArray(FILE_SIGNATURE_SIZE);
        const jbyte fileSig[FILE_SIGNATURE_SIZE] = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
        threadEnv->SetByteArrayRegion(fileSignature, 0, FILE_SIGNATURE_SIZE, fileSig);
        outgoing_bytes.write(fileSignature, 0, FILE_SIGNATURE_SIZE);

        // generate random IV
        unsigned char iv[AES_BLOCK_SIZE];

        unsigned seed = std::chrono::steady_clock::now().time_since_epoch().count();
        std::mt19937 rand_engine(seed);
        std::uniform_int_distribution<int> random_number(
          std::numeric_limits<int>::min(),
          std::numeric_limits<int>::max()
        );

        for(size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
          iv[i] = random_number(rand_engine);
        }

        jbyteArray jniIV = threadEnv->NewByteArray(AES_BLOCK_SIZE);
        threadEnv->SetByteArrayRegion(jniIV, 0, AES_BLOCK_SIZE, reinterpret_cast<jbyte *>(iv));
        outgoing_bytes.write(jniIV, 0, AES_BLOCK_SIZE);

        jboolean JNIException = threadEnv->ExceptionCheck();

        if (JNIException) {
          threadEnv->ExceptionDescribe();
          outgoing_bytes.close();
          incoming_bytes.close();
          outputFile.Delete();
          continue;
        }

        jbyteArray prevJniBuffer = threadEnv->NewByteArray(BUFFER_SIZE);
        jint prevBufferSize = incoming_bytes.read(prevJniBuffer);
        jbyte* prevBuffer = nullptr;

        jbyteArray nextJniBuffer = threadEnv->NewByteArray(BUFFER_SIZE);
        jint nextBufferSize = 0;

        while (prevBufferSize == BUFFER_SIZE) {
          nextBufferSize = incoming_bytes.read(nextJniBuffer);
          if (nextBufferSize < 1) {
            break;
          }

          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, NULL);
          for (size_t index = 0; index < prevBufferSize; index += AES_BLOCK_SIZE) {
            aes_scheme.blockEncrypt(
              reinterpret_cast<unsigned char *>(prevBuffer + index),
              reinterpret_cast<unsigned char *>(encryptedBuffer + index),
              reinterpret_cast<unsigned char *>(iv)
            );
          }
          threadEnv->ReleasePrimitiveArrayCritical(prevJniBuffer, prevBuffer, JNI_ABORT);

          threadEnv->SetByteArrayRegion(
            prevJniBuffer, 0, prevBufferSize,
            reinterpret_cast<jbyte *>(encryptedBuffer));
          outgoing_bytes.write(prevJniBuffer, 0, prevBufferSize);

          std::swap(prevJniBuffer, nextJniBuffer);
          std::swap(prevBufferSize, nextBufferSize);
        }

        prevBufferSize = (prevBufferSize < 1) ? 0 : prevBufferSize;

        size_t remainingBlocks = prevBufferSize / AES_BLOCK_SIZE;
        size_t remainingBytes = prevBufferSize % AES_BLOCK_SIZE;
        size_t index = 0;

        bool excludeLastBlock = (remainingBlocks && remainingBytes == 0);

        if (remainingBlocks) {
          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, NULL);

          for (; index < remainingBlocks - excludeLastBlock; ++index) {
            aes_scheme.blockEncrypt(
              reinterpret_cast<unsigned char *>(prevBuffer + (index * AES_BLOCK_SIZE)),
              reinterpret_cast<unsigned char *>(encryptedBuffer + (index * AES_BLOCK_SIZE)), iv
            );
          }

          threadEnv->ReleasePrimitiveArrayCritical(prevJniBuffer, prevBuffer, JNI_ABORT);
          threadEnv->SetByteArrayRegion(
            prevJniBuffer, 0, (remainingBlocks - excludeLastBlock) * AES_BLOCK_SIZE,
            reinterpret_cast<jbyte *>(encryptedBuffer)
          );
          outgoing_bytes.write(prevJniBuffer, 0, (remainingBlocks - excludeLastBlock) * AES_BLOCK_SIZE);
        }

        Krypt::ByteArray cipher;

        prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, NULL);
        if (excludeLastBlock) {
          cipher = aes_scheme.encrypt(
            reinterpret_cast<unsigned char *>(prevBuffer + (index * AES_BLOCK_SIZE)), AES_BLOCK_SIZE, iv
          );
        } else {
          cipher = aes_scheme.encrypt(
            reinterpret_cast<unsigned char *>(prevBuffer + (index * AES_BLOCK_SIZE)), remainingBytes, iv
          );
        }
        threadEnv->ReleasePrimitiveArrayCritical(prevJniBuffer, prevBuffer, JNI_ABORT);

        threadEnv->SetByteArrayRegion(
          prevJniBuffer, 0, cipher.length,
          reinterpret_cast<jbyte *>(cipher.array));
        outgoing_bytes.write(prevJniBuffer, 0, cipher.length);

        if (threadEnv->ExceptionCheck()) {
          __android_log_write(ANDROID_LOG_ERROR, "C++ Encryption", "JNI Exception Occurred At Last Check");
          threadEnv->ExceptionDescribe();
          outgoing_bytes.close();
          incoming_bytes.close();
          outputFile.Delete();
        } else {
          cnt++;
        }
      } catch (const char* err) {
        __android_log_write(ANDROID_LOG_ERROR, "C++ Encryption ", std::string(target_file + " : " + std::string(err)).c_str());
      } catch (const std::exception& err) {
        __android_log_write(ANDROID_LOG_ERROR, "C++ Encryption ", std::string(target_file + " : " + std::string(err.what())).c_str());
      }  catch (...) {
        __android_log_write(ANDROID_LOG_ERROR, "C++ Encryption ", std::string(target_file + " : Unknown C++ Exception Occurred").c_str());
      }
    }

    delete[] encryptedBuffer;

    if (isDifferentThread == JNI_EDETACHED) {
      javaVM->DetachCurrentThread();
    }
  };

  int physical_threads = std::thread::hardware_concurrency();

  std::vector<std::thread> threads;

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    vector_mtx.lock();
    bool notEmpty = !file_queue.isEmpty();
    vector_mtx.unlock();

    if (notEmpty) {
      threads.push_back(std::thread(encrypt_lambda));
    }
  }

  vector_mtx.lock();
  bool notEmpty = !file_queue.isEmpty();
  vector_mtx.unlock();

  if (notEmpty) {
    encrypt_lambda();
  }

  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i].join();
  }

  env->DeleteGlobalRef(DocumentFileClass);
  env->DeleteGlobalRef(globalThis);
  env->DeleteGlobalRef(globalOutputPath);

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

  env->ReleaseByteArrayElements(key_file, aeskey, 0);

  std::atomic<jint> cnt(0);
  std::mutex vector_mtx;

  if (BUFFER_SIZE % AES_BLOCK_SIZE != 0 || BUFFER_SIZE <= AES_BLOCK_SIZE) {
    return RESULT_CODE::INVALID_INTERNAL_BUFFER_SIZE;
  }

  JavaVM* javaVM;
  env->GetJavaVM((_JavaVM**) &javaVM);
  jobject DocumentFileClass = env->NewGlobalRef((jobject) env->FindClass("androidx/documentfile/provider/DocumentFile"));
  jobject globalThis = env->NewGlobalRef(thiz);
  jobject globalOutputPath = env->NewGlobalRef(output_path);

  auto decrypt_lambda = [&] () -> void {
    JNIEnv* threadEnv;

    jint isDifferentThread = javaVM->GetEnv((void **) &threadEnv, JNI_VERSION_1_6);

    if (isDifferentThread == JNI_EDETACHED) {
      javaVM->AttachCurrentThread((_JNIEnv**) &threadEnv, NULL);
    } else if (isDifferentThread == JNI_OK) {
      threadEnv = env;
    } else {
      __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption ", "thread attachment failed");
      return;
    }

    bool run_thread = true;

    Bytes *decryptedBuffer = new Bytes[BUFFER_SIZE];

    std::string target_file;

    while (run_thread) {
      try {
        Uri target_uri(threadEnv);

        vector_mtx.lock();
        run_thread = !file_queue.isEmpty(threadEnv);

        if (run_thread) {
          target_uri._thiz = file_queue.remove(threadEnv, 0)._thiz;
          target_uri._Jclass = threadEnv->GetObjectClass(target_uri._thiz);
          jstring filename = getFileName(threadEnv, globalThis, target_uri._thiz);
          const char *c_filename_buffer = threadEnv->GetStringUTFChars(filename, NULL);
          target_file = std::string(c_filename_buffer);
          threadEnv->ReleaseStringUTFChars(filename, c_filename_buffer);
        } else {
          vector_mtx.unlock();
          break;
        }

        vector_mtx.unlock();

        InputStream incoming_bytes = InputStream(
          threadEnv,
          openFileUriInputStream(threadEnv, globalThis, target_uri._thiz)
        );

        InputStream readIncomingByteLength = InputStream(
          threadEnv,
          openFileUriInputStream(threadEnv, globalThis, target_uri._thiz)
        );

        std::string outfname(target_file);
        std::string fileExtension = "";

        if (outfname.size() > FILE_EXTENSION_SIZE) {
          fileExtension = outfname.substr(outfname.size() - FILE_EXTENSION_SIZE, FILE_EXTENSION_SIZE);
        }

        outfname = outfname.substr(0, outfname.size() - FILE_EXTENSION_SIZE);

        jstring jniOutputFileName = threadEnv->NewStringUTF(outfname.c_str());

        jstring mimeType = threadEnv->NewStringUTF("application/octet-stream");

        Uri treeUri(threadEnv, globalOutputPath);
        Context folder_ctx = Activity(threadEnv, globalThis).getApplicationContext();

        DocumentFile folder = DocumentFile::fromTreeUri(
          threadEnv,
          folder_ctx,
          treeUri,
          (jclass) DocumentFileClass
        );

        DocumentFile outputFile = folder.createFile(mimeType, jniOutputFileName);
        OutputStream outgoing_bytes = Activity(threadEnv, globalThis).getApplicationContext().getContentResolver().openOutputStream(outputFile.getUri());

        jbyteArray fileSignature = threadEnv->NewByteArray(FILE_SIGNATURE_SIZE);
        int incoming_byte_size = incoming_bytes.read(fileSignature);

        if (incoming_byte_size != FILE_SIGNATURE_SIZE) {
          incoming_bytes.close();
          outgoing_bytes.close();
          outputFile.Delete();
          continue;
        }

        const jbyte fileSig[FILE_SIGNATURE_SIZE] = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
        jbyte *fileSigRead = threadEnv->GetByteArrayElements(fileSignature, NULL);

        bool fileSignatureIncorrect = false;
        for (int i = 0; i < FILE_SIGNATURE_SIZE; ++i) {
          if (fileSig[i] != fileSigRead[i]) {
            fileSignatureIncorrect = true;
            break;
          }
        }

        if (fileSignatureIncorrect) {
          incoming_bytes.close();
          outgoing_bytes.close();
          outputFile.Delete();
          continue;
        }

        jint length;
        jbyteArray jniBuffer = threadEnv->NewByteArray(BUFFER_SIZE);
        jbyteArray jniIV = threadEnv->NewByteArray(AES_BLOCK_SIZE);
        incoming_bytes.read(jniIV);
        jbyte *iv = threadEnv->GetByteArrayElements(jniIV, NULL);

        std::string properFileExtension = ".bthl";

        jboolean signFailed = std::memcmp(fileSigRead, fileSig, FILE_SIGNATURE_SIZE);
        jboolean wrongFileExtension = fileExtension != properFileExtension;
        jboolean JNIException = threadEnv->ExceptionCheck();

        threadEnv->ReleaseByteArrayElements(fileSignature, fileSigRead, 0);

        if (signFailed || wrongFileExtension || JNIException) {
          if (JNIException) {
            threadEnv->ExceptionDescribe();
          }
          incoming_bytes.close();
          outgoing_bytes.close();
          outputFile.Delete();
          continue;
        }

        jbyteArray prevJniBuffer = threadEnv->NewByteArray(BUFFER_SIZE);
        jint prevBufferSize = incoming_bytes.read(prevJniBuffer);
        jbyte* prevBuffer = nullptr;

        jbyteArray nextJniBuffer = threadEnv->NewByteArray(BUFFER_SIZE);
        jint nextBufferSize = 0;

        while (prevBufferSize == BUFFER_SIZE) {
          nextBufferSize = incoming_bytes.read(nextJniBuffer);
          if (nextBufferSize < 1) {
            break;
          }

          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, NULL);
          for (size_t index = 0; index < prevBufferSize; index += AES_BLOCK_SIZE) {
            aes_scheme.blockDecrypt(
              reinterpret_cast<unsigned char *>(prevBuffer + index),
              reinterpret_cast<unsigned char *>(decryptedBuffer + index),
              reinterpret_cast<unsigned char *>(iv)
            );
          }
          threadEnv->ReleasePrimitiveArrayCritical(prevJniBuffer, prevBuffer, JNI_ABORT);

          threadEnv->SetByteArrayRegion(
            prevJniBuffer, 0, prevBufferSize,
            reinterpret_cast<jbyte *>(decryptedBuffer));
          outgoing_bytes.write(prevJniBuffer, 0, prevBufferSize);

          std::swap(prevJniBuffer, nextJniBuffer);
          std::swap(prevBufferSize, nextBufferSize);
        }

        prevBufferSize = (prevBufferSize < 1) ? 0 : prevBufferSize;

        size_t remainingBlocks = prevBufferSize / AES_BLOCK_SIZE;
        size_t remainingBytes = prevBufferSize % AES_BLOCK_SIZE;
        size_t index = 0;

        bool excludeLastBlock = (remainingBlocks && remainingBytes == 0);

        if (remainingBlocks) {
          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, NULL);

          for (; index < remainingBlocks - excludeLastBlock; ++index) {
            aes_scheme.blockDecrypt(
              reinterpret_cast<unsigned char *>(prevBuffer + (index * AES_BLOCK_SIZE)),
              reinterpret_cast<unsigned char *>(decryptedBuffer + (index * AES_BLOCK_SIZE)),
              reinterpret_cast<unsigned char *>(iv)
            );
          }

          threadEnv->ReleasePrimitiveArrayCritical(prevJniBuffer, prevBuffer, JNI_ABORT);
          threadEnv->SetByteArrayRegion(
            prevJniBuffer, 0, (remainingBlocks - excludeLastBlock) * AES_BLOCK_SIZE,
            reinterpret_cast<jbyte *>(decryptedBuffer)
          );

          outgoing_bytes.write(prevJniBuffer, 0, (remainingBlocks - excludeLastBlock) * AES_BLOCK_SIZE);
        }

        Krypt::ByteArray recover;

        prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, NULL);

        if (excludeLastBlock) {
          recover = aes_scheme.decrypt(
            reinterpret_cast<unsigned char *>(prevBuffer + (index * AES_BLOCK_SIZE)),
            AES_BLOCK_SIZE,
            reinterpret_cast<unsigned char *>(iv)
          );
        } else {
          recover = aes_scheme.decrypt(
            reinterpret_cast<unsigned char *>(prevBuffer + (index * AES_BLOCK_SIZE)),
            remainingBytes,
            reinterpret_cast<unsigned char *>(iv)
          );
        }

        threadEnv->ReleasePrimitiveArrayCritical(prevJniBuffer, prevBuffer, JNI_ABORT);
        threadEnv->ReleaseByteArrayElements(jniIV, iv, 0);

        threadEnv->SetByteArrayRegion(
          prevJniBuffer, 0, recover.length,
          reinterpret_cast<jbyte *>(recover.array));
        outgoing_bytes.write(prevJniBuffer, 0, recover.length);

        if (threadEnv->ExceptionCheck()) {
          __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption", "JNI Exception Occurred At Last Check");
          threadEnv->ExceptionDescribe();
          incoming_bytes.close();
          outgoing_bytes.close();
          outputFile.Delete();
        } else {
          cnt++;
        }
      } catch (const char* err) {
        __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption ", std::string(target_file + " : " + std::string(err)).c_str());
      } catch (const std::exception& err) {
        __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption ", std::string(target_file + " : " + std::string(err.what())).c_str());
      }  catch (...) {
        __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption ", std::string(target_file + " : Unknown C++ Exception Occurred").c_str());
      }
    }

    delete[] decryptedBuffer;

    if (isDifferentThread == JNI_EDETACHED) {
      javaVM->DetachCurrentThread();
    }
  };

  int physical_threads = std::thread::hardware_concurrency();

  std::vector<std::thread> threads;

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    vector_mtx.lock();
    bool notEmpty = !file_queue.isEmpty();
    vector_mtx.unlock();

    if (notEmpty) {
      threads.push_back(std::thread(decrypt_lambda));
    }
  }

  vector_mtx.lock();
  bool notEmpty = !file_queue.isEmpty();
  vector_mtx.unlock();

  if (notEmpty) {
    decrypt_lambda();
  }

  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i].join();
  }

  env->DeleteGlobalRef(DocumentFileClass);
  env->DeleteGlobalRef(globalThis);
  env->DeleteGlobalRef(globalOutputPath);

  return cnt.load(std::memory_order_relaxed);
}

extern "C" JNIEXPORT jint JNICALL Java_com_application_bethela_BethelaActivity_checkAesCodeImplementation (
  JNIEnv *env, jobject thiz
) {
  return Krypt::BlockCipher::AES::aes_implementation();
}