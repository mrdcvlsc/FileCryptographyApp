package com.application.bethela;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;

public class BethelaActivity extends AppCompatActivity {

    static {
        System.loadLibrary("bethela");
    }

    private Uri uriOutputFolder;
    private Uri uriKeyFile;
    private ArrayList<Uri> urisFiles;
    private TextView tvPassword;
    private TextView tvKeyFile;
    private TextView tvFiles;
    private TextView tvSaveFolder;
    private String password;

    private boolean keyFileMode;

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

    private byte[] generateKeyPassword () {
        // TODO: generate an encryption/decryption key from a given password (key derivation)
        return null;
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

            keyInputStream.read(keySizeBuffer);
            int keySize = 0;
            for (int i = 0; i < keySizeBuffer.length; ++i) {
                keySize <<= Byte.SIZE;
                keySize |= keySizeBuffer[keySizeBuffer.length - 1 - i];
            }

            byte[] fileSig = {0x42, 0x45, 0x54, 0x48, 0x45, 0x4c, 0x41};
            byte[] readFileSig = new byte[fileSig.length];
            keyInputStream.read(readFileSig);

            keySize -= readFileSig.length;

            Log.d("getKeyFile: fileSig", Arrays.toString(fileSig));
            Log.d("getKeyFile: readFileSig", Arrays.toString(readFileSig));
            Log.d("getKeyFile: keySize", "" + keySize);

            byte[] key = new byte[keySize];
            keyInputStream.read(key);

            return key;
        } catch (Exception err) {
            Log.d("getKeyFile: Error", err.getMessage());
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

    public void btnGenerateFileKey (View v) {
        // TODO: btnGenerateFileKey
    }

    public boolean ready() {
        if (!keyFileMode) {
            password = tvPassword.getText().toString();
        }

        if (keyFileMode && uriKeyFile == null) {
            Toast.makeText(this, "Select a key file", Toast.LENGTH_SHORT).show();
            return false;
        } else if (!keyFileMode && password == null) {
            Toast.makeText(this, "Input a password", Toast.LENGTH_SHORT).show();
            return false;
        } else if (!keyFileMode && password.length() < 8) {
            Toast.makeText(this, "Password length should be 8 or greater", Toast.LENGTH_SHORT).show();
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
        if (ready()) {
            byte[] key;

            if (keyFileMode) {
                key = getKeyFile(uriKeyFile);;
            } else {
                key = sha256(tvPassword.getText().toString(), 5000);
            }

            if (key == null) {
                if (keyFileMode) {
                    Toast.makeText(this, "KeyFile error", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "KeyPassword error", Toast.LENGTH_SHORT).show();
                }
                return;
            }

            try {
                int res = encryptFiles(key, urisFiles, uriOutputFolder);

                int fail_bit = (res >> 31) & 0x1;

                if (fail_bit == 0x1) {
                    res = ~((0x1 << 31) | ~res);
                    Toast.makeText(this, "Some files(" + res + ") encrypted, others FAILED!", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "All files(" + res + ") encrypted", Toast.LENGTH_SHORT).show();
                }
            } catch (Exception err) {
                Toast.makeText(this, "Encryption error occur", Toast.LENGTH_SHORT).show();
            }
        }
    }

    public void btnDecryptFiles (View v) {
        if (ready()) {
            byte[] key;

            if (keyFileMode) {
                key = getKeyFile(uriKeyFile);;
            } else {
                key = sha256(tvPassword.getText().toString(), 5000);
            }

            if (key == null) {
                if (keyFileMode) {
                    Toast.makeText(this, "KeyFile error", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "KeyPassword error", Toast.LENGTH_SHORT).show();
                }
                return;
            }

            try {
                int res = decryptFiles(key, urisFiles, uriOutputFolder);

                int fail_bit = (res >> 31) & 0x1;

                if (fail_bit == 0x1) {
                    res = ~((0x1 << 31) | ~res);
                    Toast.makeText(this, "Some files(" + res + ") decrypted, others FAILED!", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "All files(" + res + ") decrypted", Toast.LENGTH_SHORT).show();
                }
            } catch (Exception err) {
                Toast.makeText(this, "Decryption error occur", Toast.LENGTH_SHORT).show();
            }
        }
    }

    // ##################################################################################
    // native methods
    // ##################################################################################

    private native int encryptFiles(byte[] keyFile, ArrayList<Uri> targetFiles, Uri outputPath);
    private native int decryptFiles(byte[] keyFile, ArrayList<Uri> targetFiles, Uri outputPath);
}