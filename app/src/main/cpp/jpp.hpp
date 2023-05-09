#ifndef APPBETHELA_JPP_HPP
#define APPBETHELA_JPP_HPP

#include <jni.h>
#include <iostream>
#include <vector>

/// Java classes as C++ classes.
namespace Jpp {
  // ############################################################
  // Jpp Class Forward Declarations.
  struct Activity;
  struct Context;
  struct ContentResolver;
  struct Cursor;
  struct DocumentFile;
  struct Uri;
  struct InputStream;
  struct OutputStream;

  // ############################################################
  // Class Declarations
  // - Constructor Declaration.
  // - Function Declarations for "Own Class" return types.
  // - Function Declarations for "JNI" return types.
  // - Function Definitions for "Jpp Class" return types, Declare on methods section.

  // "Declaration" means complete.
  // "Definition" means only the signatures.

  struct Uri {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    Uri(JNIEnv *env) {
      this->_env = env;
    }

    Uri(JNIEnv *env, jobject uri) {
      this->_env = env;
      this->_thiz = uri;
//      _Jclass = env->FindClass("android/net/Uri");
      _Jclass = env->GetObjectClass(_thiz);
    }
  };

  struct InputStream {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    jmethodID _m_read;
    jmethodID _m_close;

    InputStream(JNIEnv *env, jobject input_stream) {
      this->_env = env;
      this->_thiz = input_stream;
//      _Jclass = env->FindClass("java/io/InputStream");
      _Jclass = env->GetObjectClass(_thiz);

      _m_read = env->GetMethodID(_Jclass, "read", "([B)I");

      _m_close = env->GetMethodID(_Jclass, "close", "()V");
    }

    jint read(jbyteArray b) {
      return _env->CallIntMethod(_thiz, _m_read, b);
    };

    void close() {
      _env->CallVoidMethod(_thiz, _m_close);
    }
  };

  struct OutputStream {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    jmethodID _m_write;
    jmethodID _m_close;
    jmethodID _m_flush;

    OutputStream(JNIEnv *env, jobject output_stream) {
      this->_env = env;
      this->_thiz = output_stream;
//      _Jclass = env->FindClass("java/io/OutputStream");
      _Jclass = env->GetObjectClass(_thiz);

      _m_write = env->GetMethodID(_Jclass, "write", "([BII)V");

      _m_close = env->GetMethodID(_Jclass, "close", "()V");

      _m_flush = env->GetMethodID(_Jclass, "flush", "()V");
    }

    void write(jbyteArray b, jint off, jint len) {
      _env->CallVoidMethod(_thiz, _m_write, b, off, len);
    }

    void close() {
      _env->CallVoidMethod(_thiz, _m_close);
    }

    void flush() {
      _env->CallVoidMethod(_thiz, _m_flush);
    }
  };

  struct DocumentFile {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    jmethodID _m_getUri;
    jmethodID _m_createFile;
    jmethodID _m_delete;
    static jmethodID _m_fromTreeUri;

    DocumentFile(JNIEnv *env, jobject document_file) {
      this->_env = env;
      this->_thiz = document_file;
//      _Jclass = env->FindClass("androidx/documentfile/provider/DocumentFile");
      _Jclass = env->GetObjectClass(_thiz);

      _m_getUri = env->GetMethodID(
        _Jclass,
        "getUri",
        "()Landroid/net/Uri;"
      );

      _m_createFile = env->GetMethodID(
        _Jclass,
        "createFile",
        "(Ljava/lang/String;Ljava/lang/String;)Landroidx/documentfile/provider/DocumentFile;"
      );

      _m_delete = env->GetMethodID(
        _Jclass,
        "delete",
        "()Z"
      );
    }

    static DocumentFile fromTreeUri(JNIEnv *static_env, Context const &context, Uri const &treeUri, jclass DocumentFileClass);

    Uri getUri();

    DocumentFile createFile(jstring mimeType, jstring displayName);

    jboolean Delete() {
      return _env->CallBooleanMethod(_thiz, _m_delete);
    }
  };

  struct Activity {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    jmethodID _m_getApplicationContext;

    Activity(JNIEnv *env, jobject activity) {
      this->_env = env;
      this->_thiz = activity;
//      _Jclass = env->GetObjectClass(_thiz);
      _Jclass = env->GetObjectClass(_thiz);

      _m_getApplicationContext = env->GetMethodID(
        _Jclass,
        "getApplicationContext",
        "()Landroid/content/Context;"
      );
    }

    Context getApplicationContext();
  };

  struct Context {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    jmethodID _m_getContentResolver;

    Context(JNIEnv *env, jobject context) {
      this->_env = env;
      this->_thiz = context;
//      _Jclass = env->FindClass("android/content/Context");
      _Jclass = env->GetObjectClass(_thiz);

      _m_getContentResolver = env->GetMethodID(
        _Jclass,
        "getContentResolver",
        "()Landroid/content/ContentResolver;"
      );
    }

    ContentResolver getContentResolver();
  };

  struct ContentResolver {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    jmethodID _m_query;
    jmethodID _m_openInputStream;
    jmethodID _m_openOutputStream;

    ContentResolver(JNIEnv *env, jobject content_resolver) {
      this->_env = env;
      this->_thiz = content_resolver;
//      _Jclass = env->FindClass("android/content/ContentResolver");
      _Jclass = env->GetObjectClass(_thiz);

      _m_query = env->GetMethodID(
        _Jclass,
        "query",
        "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"
      );

      _m_openInputStream = env->GetMethodID(
        _Jclass,
        "openInputStream",
        "(Landroid/net/Uri;)Ljava/io/InputStream;"
      );

      _m_openOutputStream = env->GetMethodID(
        _Jclass,
        "openOutputStream",
        "(Landroid/net/Uri;)Ljava/io/OutputStream;"
      );
    }

    /**
     * @param uri Uri
     * @param projection String[]
     * @param selection String
     * @param selectionArgs String[]
     * @param sortOrder String
     */
    Cursor
    query(Uri const &uri, jobjectArray projection, jstring selection, jobjectArray selectionArgs,
          jstring sortOrder);

    InputStream openInputStream(Uri const &uri);

    OutputStream openOutputStream(Uri const &uri);
  };

  struct Cursor {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;
    bool _closed;

    jmethodID _m_moveToFirst;
    jmethodID _m_getString;
    jmethodID _m_getColumnIndexOrThrow;
    jmethodID _m_close;

    Cursor(JNIEnv *env, jobject cursor) {
      this->_env = env;
      this->_thiz = cursor;
//      _Jclass = env->FindClass("android/database/Cursor");
      _Jclass = env->GetObjectClass(_thiz);

      _closed = false;

      _m_moveToFirst = env->GetMethodID(
        _Jclass,
        "moveToFirst", "()Z"
      );

      _m_getString = env->GetMethodID(
        _Jclass,
        "getString",
        "(I)Ljava/lang/String;"
      );

      _m_getColumnIndexOrThrow = env->GetMethodID(
        _Jclass,
        "getColumnIndexOrThrow",
        "(Ljava/lang/String;)I"
      );

      _m_close = env->GetMethodID(
        _Jclass,
        "close",
        "()V"
      );
    }

    jboolean moveToFirst() {
      return _env->CallBooleanMethod(_thiz, _m_moveToFirst);
    }

    jstring getString(jint columnIndex) {
      return (jstring) _env->CallObjectMethod(
        _thiz,
        _m_getString,
        columnIndex
      );
    }

    jint getColumnIndexOrThrow(jstring columnName) {
      return _env->CallIntMethod(
        _thiz,
        _m_getColumnIndexOrThrow,
        columnName
      );
    }

    void close() {
      _env->CallVoidMethod(_thiz, _m_close);
    }

    ~Cursor() {
      if (!_closed) {
        close();
      }
    }
  };

  // ############################################################
  // Method Declarations for Jpp return types.

  Context Activity::getApplicationContext() {
    return Context(_env, _env->CallObjectMethod(_thiz, _m_getApplicationContext));
  }

  ContentResolver Context::getContentResolver() {
    return ContentResolver(_env, _env->CallObjectMethod(_thiz, _m_getContentResolver));
  }

  Cursor ContentResolver::query(Uri const &uri, jobjectArray projection, jstring selection,
                                jobjectArray selectionArgs, jstring sortOrder) {
    return Cursor(_env, _env->CallObjectMethod(
      _thiz,
      _m_query,
      uri._thiz, projection, selection, selectionArgs, sortOrder
    ));
  }

  InputStream ContentResolver::openInputStream(Uri const &uri) {
    return InputStream(_env, _env->CallObjectMethod(
      _thiz,
      _m_openInputStream,
      uri._thiz
    ));
  }

  OutputStream ContentResolver::openOutputStream(Uri const &uri) {
    return OutputStream(_env, _env->CallObjectMethod(
      _thiz,
      _m_openOutputStream,
      uri._thiz
    ));
  }

  Uri DocumentFile::getUri() {
    return Uri(_env, _env->CallObjectMethod(
      _thiz,
      _m_getUri
    ));
  }

  DocumentFile DocumentFile::fromTreeUri(JNIEnv *static_env, Context const &context, Uri const &treeUri, jclass DocumentFileClass) {
    jmethodID fromTreeUri_m = static_env->GetStaticMethodID(
      DocumentFileClass,
//      static_env->FindClass("androidx/documentfile/provider/DocumentFile"),
      "fromTreeUri",
      "(Landroid/content/Context;Landroid/net/Uri;)Landroidx/documentfile/provider/DocumentFile;"
    );

    return DocumentFile(static_env, static_env->CallStaticObjectMethod(
      DocumentFileClass,
      fromTreeUri_m,
      context._thiz,
      treeUri._thiz
    ));
  }

  DocumentFile DocumentFile::createFile(jstring mimeType, jstring displayName) {
    return DocumentFile(_env, _env->CallObjectMethod(
      _thiz,
      _m_createFile,
      mimeType, displayName
    ));
  }

  // ############################################################
  // Array List

  template<typename T>
  struct ArrayList {
    JNIEnv *_env;
    jclass _Jclass;
    jobject _thiz;

    jmethodID _m_size;
    jmethodID _m_get;
    jmethodID _m_remove;
    jmethodID _m_isEmpty;

    ArrayList(JNIEnv *env, jobject array_list) {
      this->_env = env;
//      this->_Jclass = env->FindClass("java/util/ArrayList");
      _thiz = _env->NewGlobalRef(array_list);
      _Jclass = env->GetObjectClass(_thiz);

      _m_size = env->GetMethodID(_Jclass, "size", "()I");
      _m_get = env->GetMethodID(_Jclass, "get", "(I)Ljava/lang/Object;");
      _m_remove = env->GetMethodID(_Jclass, "remove", "(I)Ljava/lang/Object;");
      _m_isEmpty = env->GetMethodID(_Jclass, "isEmpty", "()Z");
    }

    ~ArrayList() {
      _env->DeleteGlobalRef(_thiz);
    }

    // self thread method
    jint size() {
      return _env->CallIntMethod(_thiz, _m_size);
    }

    T get(jint index) {
      return T(_env, _env->CallObjectMethod(_thiz, _m_get, index));
    }

    T remove(jint index) {
      return T(_env, _env->CallObjectMethod(_thiz, _m_remove, index));
    }

    jboolean isEmpty() {
      return _env->CallBooleanMethod(_thiz, _m_isEmpty);
    }

    // use this methods if the array list is accessed in other threads

    jint size(JNIEnv *env) {
      return env->CallIntMethod(_thiz, _m_size);
    }

    T get(JNIEnv *env, jint index) {
      return T(env, env->CallObjectMethod(_thiz, _m_get, index));
    }

    T remove(JNIEnv *env, jint index) {
      return T(env, env->CallObjectMethod(_thiz, _m_remove, index));
    }

    jboolean isEmpty(JNIEnv* env) {
      return env->CallBooleanMethod(_thiz, _m_isEmpty);
    }
  };
}

#endif //APPBETHELA_JPP_HPP
