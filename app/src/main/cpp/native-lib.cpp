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
#include "Krypt/src/Krypt.hpp"
#include "jpp.hpp"

using namespace Krypt;
using namespace Jpp;

constexpr static jsize MB = 16;
constexpr static jsize BUFFER_SIZE = MB * 1024 * 1024;

/// 5 characters.
constexpr static size_t FILE_EXTENSION_SIZE = 5;

/// 7 byte file signature.
constexpr static jint FILE_SIGNATURE_SIZE = 7;

/// the size of one AES block in bytes.
constexpr static jint AES_BLOCK_SIZE = 16;

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

  if (BUFFER_SIZE % AES_BLOCK_SIZE != 0 || BUFFER_SIZE <= AES_BLOCK_SIZE) {
    return 0xffffffff; // invalid buffer size
  }

  JavaVM* javaVM;
  env->GetJavaVM((_JavaVM**) &javaVM);
  jclass DocumentFileClass = env->FindClass("androidx/documentfile/provider/DocumentFile");

  auto encrypt_lambda = [&] () -> void {
    JNIEnv* threadEnv;
    javaVM->AttachCurrentThread((_JNIEnv**) &threadEnv, NULL);

    bool run_thread = true;

    Bytes *encryptedBuffer = new Bytes[BUFFER_SIZE];

    while (run_thread) {
      try {
        std::string target_file;
        Uri target_uri(threadEnv);

        vector_mtx.lock();
        run_thread = !file_queue.isEmpty(threadEnv);

        if (run_thread) {
          target_uri._thiz = file_queue.remove(file_queue.size() - 1)._thiz;
          target_uri._Jclass = threadEnv->GetObjectClass(target_uri._thiz);
          jstring filename = getFileName(threadEnv, thiz, target_uri._thiz);
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
          openFileUriInputStream(threadEnv, thiz, target_uri._thiz)
        );

        std::string outfname(target_file + ".bthl");
        jstring jniOutputFileName = threadEnv->NewStringUTF(outfname.c_str());

        jstring mimeType = threadEnv->NewStringUTF("application/octet-stream");
        DocumentFile folder = DocumentFile::fromTreeUri(
          threadEnv,
          Activity(threadEnv, thiz).getApplicationContext(),
          Uri(threadEnv, output_path), DocumentFileClass
        );

        DocumentFile outputFile = folder.createFile(mimeType, jniOutputFileName);

        OutputStream outgoing_bytes = Activity(threadEnv, thiz).getApplicationContext().getContentResolver().openOutputStream(outputFile.getUri());

        jbyteArray fileSignature = threadEnv->NewByteArray(FILE_SIGNATURE_SIZE);
        const jbyte fileSig[FILE_SIGNATURE_SIZE] = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
        threadEnv->SetByteArrayRegion(fileSignature, 0, FILE_SIGNATURE_SIZE, fileSig);
        outgoing_bytes.write(fileSignature, 0, FILE_SIGNATURE_SIZE);

        jint length;
        jbyteArray jniBuffer = threadEnv->NewByteArray(BUFFER_SIZE);

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

        while ((length = incoming_bytes.read(jniBuffer)) > 0) {
          jbyte *buffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(jniBuffer, NULL);

          if (length == BUFFER_SIZE) {
            for (size_t index = 0; index < length; index += AES_BLOCK_SIZE) {
              aes_scheme.blockEncrypt(
                reinterpret_cast<unsigned char *>(buffer + index),
                reinterpret_cast<unsigned char *>(encryptedBuffer + index),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            threadEnv->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            threadEnv->SetByteArrayRegion(
              jniBuffer, 0, length,
              reinterpret_cast<jbyte *>(encryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, length);
          } else {
            size_t remaining_blocks = length / AES_BLOCK_SIZE;
            size_t index;

            for (index = 0; index < remaining_blocks - 1; ++index) {
              aes_scheme.blockEncrypt(
                reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK_SIZE)),
                reinterpret_cast<unsigned char *>(encryptedBuffer + (index * AES_BLOCK_SIZE)),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            threadEnv->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            threadEnv->SetByteArrayRegion(
              jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK_SIZE,
              reinterpret_cast<jbyte *>(encryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK_SIZE);

            ByteArray recover = aes_scheme.encrypt(
              reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK_SIZE)),
              AES_BLOCK_SIZE, reinterpret_cast<unsigned char *>(iv)
            );

            threadEnv->SetByteArrayRegion(
              jniBuffer, 0, recover.length,
              reinterpret_cast<jbyte *>(recover.array));
            outgoing_bytes.write(jniBuffer, 0, recover.length);
          }
        }

        if (threadEnv->ExceptionCheck()) {
          threadEnv->ExceptionDescribe();
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

    javaVM->DetachCurrentThread();
  };

  int physical_threads = std::thread::hardware_concurrency();

  std::vector<std::thread> threads;

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    vector_mtx.lock();
    threads.push_back(std::thread(encrypt_lambda));
    vector_mtx.unlock();
  }

//  encrypt_lambda();

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    threads[i].join();
  }

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

  if (BUFFER_SIZE % AES_BLOCK_SIZE != 0 || BUFFER_SIZE <= AES_BLOCK_SIZE) {
    return 0xffffffff; // invalid buffer size
  }

  JavaVM* javaVM;
  env->GetJavaVM((_JavaVM**) &javaVM);
  jobject DocumentFileClass = env->NewGlobalRef((jobject) env->FindClass("androidx/documentfile/provider/DocumentFile"));
  jobject globalThis = env->NewGlobalRef(thiz);
  jobject globalOutputPath = env->NewGlobalRef(output_path);

  auto decrypt_lambda = [&] () -> void {
    __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "start");
    JNIEnv* threadEnv;
    javaVM->AttachCurrentThread((_JNIEnv**) &threadEnv, NULL);

    bool run_thread = true;

    Bytes *decryptedBuffer = new Bytes[BUFFER_SIZE];

    while (run_thread) {
      try {
        std::string target_file;
        Uri target_uri(threadEnv);

        vector_mtx.lock();
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "queue check start");
        run_thread = !file_queue.isEmpty(threadEnv);
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "queue check end");


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

        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "InputStream start");
        InputStream incoming_bytes = InputStream(
          threadEnv,
          openFileUriInputStream(threadEnv, globalThis, target_uri._thiz)
        );
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "InputStream end");


        std::string outfname(target_file);
        std::string fileExtension = "";

        if (outfname.size() > FILE_EXTENSION_SIZE) {
          fileExtension = outfname.substr(outfname.size() - FILE_EXTENSION_SIZE, FILE_EXTENSION_SIZE);
        }

        outfname = outfname.substr(0, outfname.size() - FILE_EXTENSION_SIZE);

        jstring jniOutputFileName = threadEnv->NewStringUTF(outfname.c_str());

        jstring mimeType = threadEnv->NewStringUTF("application/octet-stream");

        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Uri treeUri start");
        Uri treeUri(threadEnv, globalOutputPath);
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Uri treeUri end");

        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Context folder_ctx start");
        Context folder_ctx = Activity(threadEnv, globalThis).getApplicationContext();
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Context folder_ctx end");

        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "DocumentFile folder start");
        DocumentFile folder = DocumentFile::fromTreeUri(
          threadEnv,
          folder_ctx,
          treeUri,
          (jclass) DocumentFileClass
        );
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "DocumentFile folder end");

        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "DocumentFile outputFile start");
        DocumentFile outputFile = folder.createFile(mimeType, jniOutputFileName);
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "DocumentFile outputFile end");

        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "OutputStream outgoing_bytes start");
        OutputStream outgoing_bytes = Activity(threadEnv, globalThis).getApplicationContext().getContentResolver().openOutputStream(outputFile.getUri());
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "OutputStream outgoing_bytes start");


        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Check Block Start");
        jbyteArray fileSignature = threadEnv->NewByteArray(FILE_SIGNATURE_SIZE);
        incoming_bytes.read(fileSignature);

        const jbyte fileSig[FILE_SIGNATURE_SIZE] = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
        jbyte *fileSigRead = threadEnv->GetByteArrayElements(fileSignature, NULL);

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

        if (JNIException) {
          threadEnv->ExceptionDescribe();
        }

        if (signFailed || wrongFileExtension || JNIException) {
          outgoing_bytes.close();
          outputFile.Delete();
          continue;
        }
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Check Block End");

        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Decryption Block Start");
        while ((length = incoming_bytes.read(jniBuffer)) > 0) {
          jbyte *buffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(jniBuffer, NULL);

          if (length == BUFFER_SIZE) {
            for (size_t index = 0; index < length; index += AES_BLOCK_SIZE) {
              aes_scheme.blockDecrypt(
                reinterpret_cast<unsigned char *>(buffer + index),
                reinterpret_cast<unsigned char *>(decryptedBuffer + index),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            threadEnv->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            threadEnv->SetByteArrayRegion(
              jniBuffer, 0, length,
              reinterpret_cast<jbyte *>(decryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, length);
          } else {
            size_t remaining_blocks = length / AES_BLOCK_SIZE;
            size_t index;

            for (index = 0; index < remaining_blocks - 1; ++index) {
              aes_scheme.blockDecrypt(
                reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK_SIZE)),
                reinterpret_cast<unsigned char *>(decryptedBuffer + (index * AES_BLOCK_SIZE)),
                reinterpret_cast<unsigned char *>(iv)
              );
            }

            threadEnv->ReleasePrimitiveArrayCritical(jniBuffer, buffer, 0);
            threadEnv->SetByteArrayRegion(
              jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK_SIZE,
              reinterpret_cast<jbyte *>(decryptedBuffer));
            outgoing_bytes.write(jniBuffer, 0, (remaining_blocks - 1) * AES_BLOCK_SIZE);

            ByteArray recover = aes_scheme.decrypt(
              reinterpret_cast<unsigned char *>(buffer + (index * AES_BLOCK_SIZE)),
              AES_BLOCK_SIZE, reinterpret_cast<unsigned char *>(iv)
            );

            threadEnv->SetByteArrayRegion(
              jniBuffer, 0, recover.length,
              reinterpret_cast<jbyte *>(recover.array));
            outgoing_bytes.write(jniBuffer, 0, recover.length);
          }
        }
        __android_log_write(ANDROID_LOG_DEBUG, "Native-Thread", "Decryption Block End");

        threadEnv->ReleaseByteArrayElements(jniIV, iv, 0);

        if (threadEnv->ExceptionCheck()) {
          threadEnv->ExceptionDescribe();
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

    javaVM->DetachCurrentThread();
  };

  int physical_threads = std::thread::hardware_concurrency();

  std::vector<std::thread> threads;

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    vector_mtx.lock();
    threads.push_back(std::thread(decrypt_lambda));
    vector_mtx.unlock();
  }

//  decrypt_lambda();

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    threads[i].join();
  }

  env->DeleteGlobalRef(DocumentFileClass);
  env->DeleteGlobalRef(globalThis);
  env->DeleteGlobalRef(globalOutputPath);

  return cnt.load(std::memory_order_relaxed);
}