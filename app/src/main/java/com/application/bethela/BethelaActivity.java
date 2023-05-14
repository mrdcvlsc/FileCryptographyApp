package com.application.bethela;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.documentfile.provider.DocumentFile;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.zip.DataFormatException;

public class BethelaActivity extends AppCompatActivity {

    static {
        System.loadLibrary("bethela");
    }

    final int AES256_KEYSIZE = 32;
    private Uri uriOutputFolder;
    private Uri uriKeyFile;
    private ArrayList<Uri> urisFiles;
    private TextView tvPassword;
    private TextView tvKeyFile;
    private TextView tvFiles;
    private TextView tvSaveFolder;
    private String password;
    private boolean keyFileMode;
    private byte[] AES256_KEY;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bethela);

        tvPassword = findViewById(R.id.tv_app_passwordkey);
        tvKeyFile = findViewById(R.id.tv_app_filekey);
        tvSaveFolder = findViewById(R.id.tv_app_saveinfolder);
        tvFiles = findViewById(R.id.tv_app_selectedfiles);

        tvPassword.setVisibility(View.INVISIBLE);

        urisFiles = new ArrayList<>();

        keyFileMode = true;
    }

    // ##################################################################################
    // password selection section
    // ##################################################################################

    public void btnSelectPasswordAsKey (View v) {
        keyFileMode = false;
        tvKeyFile.setVisibility(View.INVISIBLE);
        tvPassword.setVisibility(View.VISIBLE);
    }

    // ##################################################################################
    // key selection section
    // ##################################################################################

    private final ActivityResultLauncher<Intent> keyPicker = registerForActivityResult(
        new ActivityResultContracts.StartActivityForResult(),
        new ActivityResultCallback<ActivityResult>() {
            @Override
            public void onActivityResult(ActivityResult result) {
                try {
                    Intent data = result.getData();
                    uriKeyFile = data.getData();
                    tvKeyFile.setText(getFileName(getApplicationContext(), uriKeyFile));

                    AES256_KEY = getKeyFile(uriKeyFile);
                } catch (Exception err) {
                    Log.d("keyPicker-error:", err.getMessage());
                }
            }
        }
    );

    public void btnSelectFileAsKey (View v) {
        keyFileMode = true;
        tvKeyFile.setVisibility(View.VISIBLE);
        tvPassword.setVisibility(View.INVISIBLE);

        Intent data = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        data.setType("*/*");
        data = Intent.createChooser(data, "Select Key");
        keyPicker.launch(data);
    }

    // ##################################################################################
    // files selection section
    // ##################################################################################

    private final ActivityResultLauncher<Intent> filePicker = registerForActivityResult(
        new ActivityResultContracts.StartActivityForResult(),
        new ActivityResultCallback<ActivityResult>() {
            @Override
            public void onActivityResult(ActivityResult result) {
                try {
                    Intent data = result.getData();
                    if (data.getClipData() != null) {
                        for (int i = 0; i < data.getClipData().getItemCount(); ++i) {
                            urisFiles.add(data.getClipData().getItemAt(i).getUri());
                        }
                    } else {
                        urisFiles.add(data.getData());
                    }

                    StringBuilder displayTargetFiles = new StringBuilder();

                    for (int i = 0; i < urisFiles.size(); ++i) {
                        displayTargetFiles
                            .append(getFileName(getApplicationContext(), urisFiles.get(i)))
                            .append("\n\n");
                    }

                    tvFiles.setText(displayTargetFiles.toString());
                } catch (Exception err) {
                    Log.d("filePicker-error:", err.getMessage());
                }
            }
        }
    );

    public void btnSelectFiles (View v) {
        Intent data = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        data.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        data.setType("*/*");
        data = Intent.createChooser(data, "Select files to encrypt/decrypt");
        filePicker.launch(data);
    }

    // ##################################################################################
    // folder selection section
    // ##################################################################################

    private final ActivityResultLauncher<Intent> folderPicker = registerForActivityResult(
        new ActivityResultContracts.StartActivityForResult(),
        result -> {
            if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                Intent data = result.getData();
                uriOutputFolder = data.getData();
                tvSaveFolder.setText(uriOutputFolder.getPath());
            }
        }
    );

    public void btnSelectFolder(View v) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
        folderPicker.launch(intent);
    }

    // ##################################################################################
    // clear buttons section
    // ##################################################################################

    public void btnClearFiles (View v) {
        urisFiles.clear();
        tvFiles.setText("Target Files: empty");
    }

    public void btnClearKeys (View v) {
        uriKeyFile = null;
        password = null;
        AES256_KEY = null;
        tvKeyFile.setText("Key File: empty");
        tvPassword.setText("");
    }

    // ##################################################################################
    // get methods section
    // ##################################################################################

    private static String getFileName (Context context, Uri uriFile) {
        Cursor c = context.getContentResolver().query(uriFile, null, null, null, null);
        c.moveToFirst();
        String keyFileName = c.getString(c.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME));
        c.close();
        return keyFileName;
    }

    private byte[] getKeyFile(Uri keyFile) {
        try {
            InputStream keyInputStream = getApplicationContext().getContentResolver().openInputStream(keyFile);

            byte[] keySizeBuffer = new byte[Integer.BYTES];

            for (int i = 0; i < keySizeBuffer.length; ++i) {
                keySizeBuffer[i] = 0;
            }

            int keySize = 0;
            int readLength = keyInputStream.read(keySizeBuffer);

            if (readLength == Integer.BYTES) {
                for (int i = 0; i < keySizeBuffer.length; ++i) {
                    keySize <<= Byte.SIZE;
                    keySize |= keySizeBuffer[keySizeBuffer.length - 1 - i];
                }
            } else {
                keyInputStream.close();
                throw new DataFormatException("Not a bethela file key");
            }

            byte[] fileSig = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
            byte[] readFileSig = new byte[fileSig.length];

            readLength = keyInputStream.read(readFileSig);

            if (readLength == fileSig.length) {
                for (int i = 0; i < readLength; ++i) {
                    if (fileSig[i] != readFileSig[i]) {
                        keyInputStream.close();
                        throw new DataFormatException("Not a bethela file key");
                    }
                }
            } else {
                keyInputStream.close();
                throw new DataFormatException("Not a bethela file key");
            }

            keySize -= readFileSig.length;

            Log.d("getKeyFile: fileSig", Arrays.toString(fileSig));
            Log.d("getKeyFile: readFileSig", Arrays.toString(readFileSig));
            Log.d("getKeyFile: keySize", "" + keySize);

            byte[] key = new byte[keySize];
            readLength = keyInputStream.read(key);
            if (readLength != AES256_KEYSIZE) { // Invalid AES-256 key
                keyInputStream.close();
                throw new InvalidKeyException("Not a bethela file key");
            }

            Toast.makeText(this, "KeyType: BETHELA", Toast.LENGTH_SHORT).show();
            return key;
        } catch (DataFormatException err) {
            try {
                InputStream keyInputStream = getApplicationContext().getContentResolver().openInputStream(keyFile);
                byte[] fileFirst32Bytes = new byte[AES256_KEYSIZE]; // AES-256 key

                for (int i = 0; i < AES256_KEYSIZE; ++i) {
                    fileFirst32Bytes[i] = 0;
                }

                int readLength = keyInputStream.read(fileFirst32Bytes);

                if (readLength == AES256_KEYSIZE) {
                    Toast.makeText(this, "KeyType: FILE - COMPLETE BYTES", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "KeyType: FILE - INCOMPLETE BYTES", Toast.LENGTH_SHORT).show();
                }
                return fileFirst32Bytes;
            } catch (Exception e) {
                Toast.makeText(this, "KeyType: FILE KEY ERROR", Toast.LENGTH_SHORT).show();
                return null;
            }
        } catch (InvalidKeyException err) {
            Toast.makeText(this, "KeyType: INVALID AES-256 KEY", Toast.LENGTH_SHORT).show();
            return null;
        } catch (Exception err) {
            Toast.makeText(this, "KeyType: ERROR OCCURRED", Toast.LENGTH_SHORT).show();
            return null;
        }
    }

    // ##################################################################################
    // cryptography section
    // ##################################################################################

    /// produces a 256-bit or 32 byte hash array.
    private byte[] sha256(String text, int level) {
        if (level <= 0) {
            return text.getBytes(StandardCharsets.UTF_8);
        }

        try {
            MessageDigest SHA = MessageDigest.getInstance("SHA-256");
            byte[] hash = SHA.digest(text.getBytes(StandardCharsets.UTF_8));

            for (int i = 1; i < level; ++i) {
                hash = SHA.digest(hash);
            }

            return hash;
        } catch (Exception err) {
            System.out.println(err);
            return null;
        }
    }

    private String randomAlphanumericString(int length) {
        int leftLimit = 48;
        int rightLimit = 122;
        Random random = new Random();

        return random.ints(leftLimit, rightLimit + 1)
            .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
            .limit(length)
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    }

    public void btnGenerateFileKey (View v) {
        if (uriOutputFolder == null) {
            Toast.makeText(this, "Select a save location", Toast.LENGTH_SHORT).show();
            return;
        }

        byte[] secureRandomBytes = new byte[AES256_KEYSIZE];

        try {
            SecureRandom.getInstanceStrong().nextBytes(secureRandomBytes);
        } catch (Exception err) {
            SecureRandom random = new SecureRandom();
            random.nextBytes(secureRandomBytes);
        }

        String newKeyFileName = randomAlphanumericString(8);
        DocumentFile folder = DocumentFile.fromTreeUri(this, uriOutputFolder);
        DocumentFile outputKeyFile = folder.createFile(
            "application/octet-stream",
            newKeyFileName
        );

        try {
            OutputStream outgoingBytes = getContentResolver().openOutputStream(outputKeyFile.getUri());

            byte[] fileSig = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
            byte[] keySizeBuffer = new byte[Integer.BYTES];

            int fileKeySize = fileSig.length + secureRandomBytes.length;

            for (int i = 0; i < keySizeBuffer.length; ++i) {
                keySizeBuffer[i] = (byte) fileKeySize;
                fileKeySize >>= Byte.SIZE;
            }

            outgoingBytes.write(keySizeBuffer, 0, keySizeBuffer.length);
            outgoingBytes.write(fileSig, 0, fileSig.length);
            outgoingBytes.write(secureRandomBytes, 0, secureRandomBytes.length);
            outgoingBytes.close();
        } catch (Exception err) {
            Toast.makeText(this, "Error writing to the save location", Toast.LENGTH_SHORT).show();
            outputKeyFile.delete();
        }

        Toast.makeText(this, "Key file (" + newKeyFileName + ") saved in target location", Toast.LENGTH_LONG).show();
    }

    public boolean ready() {
        if (keyFileMode && AES256_KEY == null) {
            Toast.makeText(this, "Select a key file", Toast.LENGTH_SHORT).show();
            return false;
        }

        if (!keyFileMode && tvPassword.getText().toString().isEmpty()) {
            Toast.makeText(this, "Input a password", Toast.LENGTH_SHORT).show();
            return false;
        }

        if (urisFiles.isEmpty()) {
            Toast.makeText(this, "Select target files", Toast.LENGTH_SHORT).show();
            return false;
        }

        if (uriOutputFolder == null) {
            Toast.makeText(this, "Select a save location", Toast.LENGTH_SHORT).show();
            return false;
        }

        return true;
    }

    public void btnEncryptFiles (View v) {
        int totalFiles = urisFiles.size();

        if (ready()) {
            if (!keyFileMode) {
                if (tvPassword.getText().toString().length() > 8) {
                    AES256_KEY = sha256(tvPassword.getText().toString(), 5000);
                } else {
                    Toast.makeText(this, "Password should be greater than 8 characters", Toast.LENGTH_SHORT).show();
                    return;
                }
            }

            Handler handler = new Handler(Looper.getMainLooper());
            Runnable runnable = new Runnable() {
                @Override
                public void run() {
                    int res = 0;

                    synchronized (this) {
                        res = encryptFiles(AES256_KEY, urisFiles, uriOutputFolder);
                    }

                    int finalRes = res;
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (finalRes < 0) {
                                Toast.makeText(BethelaActivity.this, "Encrypt Error, Invalid Internal Buffer", Toast.LENGTH_SHORT).show();
                            } else {
                                Toast.makeText(BethelaActivity.this, "Encrypted " + finalRes + "/" + totalFiles, Toast.LENGTH_SHORT).show();
                            }
                            btnClearFiles(null);
                        }
                    });
                }
            };

            Thread thread = new Thread(runnable);
            thread.start();
        }
    }

    public void btnDecryptFiles (View v) {
        int totalFiles = urisFiles.size();

        if (ready()) {
            if (!keyFileMode) {
                if (tvPassword.getText().toString().length() > 8) {
                    AES256_KEY = sha256(tvPassword.getText().toString(), 5000);
                } else {
                    Toast.makeText(this, "Password should be greater than 8 characters", Toast.LENGTH_SHORT).show();
                    return;
                }
            }

            Handler handler = new Handler(Looper.getMainLooper());
            Runnable runnable = new Runnable() {
                @Override
                public void run() {
                    int res = 0;

                    synchronized (this) {
                        res = decryptFiles(AES256_KEY, urisFiles, uriOutputFolder);
                    }

                    int finalRes = res;
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (finalRes < 0) {
                                Toast.makeText(BethelaActivity.this, "Decrypt Error, Invalid Internal Buffer", Toast.LENGTH_SHORT).show();
                            } else {
                                Toast.makeText(BethelaActivity.this, "Decrypted " + finalRes + "/" + totalFiles, Toast.LENGTH_SHORT).show();
                            }
                            btnClearFiles(null);
                        }
                    });
                }
            };

            Thread thread = new Thread(runnable);
            thread.start();
        }
    }

    // ##################################################################################
    // native methods
    // ##################################################################################

    private native int encryptFiles(byte[] keyFile, ArrayList<Uri> targetFiles, Uri outputPath);
    private native int decryptFiles(byte[] keyFile, ArrayList<Uri> targetFiles, Uri outputPath);
}