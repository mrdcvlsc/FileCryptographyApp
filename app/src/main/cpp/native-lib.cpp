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

#if defined(__x86_64__) || defined(_M_X64)
#define USE_AESNI
#elif defined(__aarch64__) || defined(_M_ARM64)
#define USE_ARM_AES
#endif

#include "Krypt/src/Krypt.hpp"
#include "jpp.hpp"

using namespace Krypt;
using namespace Jpp;

constexpr static jsize MB = 1;

/// release buffer size.
constexpr static jsize BUFFER_SIZE = (MB * 1024 * 1024) + ((MB * 1024 * 1024) / 8);

/// debug buffer size.
//constexpr static jsize BUFFER_SIZE = 32;

/// 5 characters.
constexpr static size_t FILE_EXTENSION_SIZE = 5;

/// 7 byte file signature.
constexpr static jint FILE_SIGNATURE_SIZE = 7;

/// the size of one AES block in bytes.
constexpr static size_t AES_BLOCK_SIZE = 16;

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

  auto *aeskey = (jbyte *) env->GetPrimitiveArrayCritical(key_file, nullptr);
  jint aeskey_size = env->GetArrayLength(key_file);

  Mode::CBC<BlockCipher::AES, Padding::PKCS_5_7> aes_scheme(
    reinterpret_cast<Bytes *>(aeskey),
    aeskey_size
  );

  env->ReleasePrimitiveArrayCritical(key_file, aeskey, JNI_ABORT);

  std::atomic<jint> cnt(0);
  std::mutex vector_mtx;

  if constexpr (BUFFER_SIZE % AES_BLOCK_SIZE != 0 || BUFFER_SIZE <= AES_BLOCK_SIZE) {
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
      javaVM->AttachCurrentThread((_JNIEnv**) &threadEnv, nullptr);
    } else if (isDifferentThread == JNI_OK) {
      threadEnv = env;
    } else {
      __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption ", "thread attachment failed");
      return;
    }

    bool run_thread = true;

    auto *encryptedBuffer = new Bytes[BUFFER_SIZE];

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
          const char *c_filename_buffer = threadEnv->GetStringUTFChars(filename, nullptr);
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

          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, nullptr);
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
          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, nullptr);

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

        prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, nullptr);
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
          reinterpret_cast<jbyte *>(cipher.array)
        );

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

  int physical_threads = (int) std::thread::hardware_concurrency();

  std::vector<std::thread> threads;

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    vector_mtx.lock();
    bool notEmpty = !file_queue.isEmpty();
    vector_mtx.unlock();

    if (notEmpty) {
      threads.emplace_back(encrypt_lambda);
    }
  }

  vector_mtx.lock();
  bool notEmpty = !file_queue.isEmpty();
  vector_mtx.unlock();

  if (notEmpty) {
    encrypt_lambda();
  }

  for (auto & thrd : threads) {
    thrd.join();
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

  auto *aeskey = (jbyte *) env->GetPrimitiveArrayCritical(key_file, nullptr);
  jint aeskey_size = env->GetArrayLength(key_file);

  Mode::CBC<BlockCipher::AES, Padding::PKCS_5_7> aes_scheme(
    reinterpret_cast<Bytes *>(aeskey),
    aeskey_size
  );

  env->ReleasePrimitiveArrayCritical(key_file, aeskey, JNI_ABORT);

  std::atomic<jint> cnt(0);
  std::mutex vector_mtx;

  if constexpr (BUFFER_SIZE % AES_BLOCK_SIZE != 0 || BUFFER_SIZE <= AES_BLOCK_SIZE) {
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
      javaVM->AttachCurrentThread((_JNIEnv**) &threadEnv, nullptr);
    } else if (isDifferentThread == JNI_OK) {
      threadEnv = env;
    } else {
      __android_log_write(ANDROID_LOG_ERROR, "C++ Decryption ", "thread attachment failed");
      return;
    }

    bool run_thread = true;

    auto *decryptedBuffer = new Bytes[BUFFER_SIZE];

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
          const char *c_filename_buffer = threadEnv->GetStringUTFChars(filename, nullptr);
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
        std::string fileExtension;

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
        auto *fileSigRead = (jbyte *) threadEnv->GetPrimitiveArrayCritical(fileSignature, nullptr);

        bool fileSignatureIncorrect = false;
        for (int i = 0; i < FILE_SIGNATURE_SIZE; ++i) {
          if (fileSig[i] != fileSigRead[i]) {
            fileSignatureIncorrect = true;
            break;
          }
        }

        jboolean signFailed = std::memcmp(fileSigRead, fileSig, FILE_SIGNATURE_SIZE);
        threadEnv->ReleasePrimitiveArrayCritical(fileSignature, fileSigRead, JNI_ABORT);

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
        jbyte *iv = threadEnv->GetByteArrayElements(jniIV, nullptr);

        std::string properFileExtension = ".bthl";

        jboolean wrongFileExtension = fileExtension != properFileExtension;
        jboolean JNIException = threadEnv->ExceptionCheck();

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

          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, nullptr);
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
            reinterpret_cast<jbyte *>(decryptedBuffer)
          );

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

          prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, nullptr);
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

        prevBuffer = (jbyte *) threadEnv->GetPrimitiveArrayCritical(prevJniBuffer, nullptr);
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

        threadEnv->ReleaseByteArrayElements(jniIV, iv, JNI_ABORT);

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

  int physical_threads = (int) std::thread::hardware_concurrency();

  std::vector<std::thread> threads;

  for (size_t i = 0; i < physical_threads - 2; ++i) {
    vector_mtx.lock();
    bool notEmpty = !file_queue.isEmpty();
    vector_mtx.unlock();

    if (notEmpty) {
      threads.emplace_back(decrypt_lambda);
    }
  }

  vector_mtx.lock();
  bool notEmpty = !file_queue.isEmpty();
  vector_mtx.unlock();

  if (notEmpty) {
    decrypt_lambda();
  }

  for (auto & thrd : threads) {
    thrd.join();
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