import java.awt.EventQueue;
import java.awt.FileDialog;

import javax.swing.JFrame;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.awt.event.ActionEvent;
import java.awt.Color;
import java.awt.Desktop;

import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

public class Frame1 {

	private JFrame frame;
	private JTextField textFieldData;
	private JTextField textFieldKey;
	// set iv static as counter
	private byte[] ivBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00 };
	// set default ket
	// key
	byte[] keyBytes = null;
	// plaintext
	byte[] inputData = null;
	private JTextField textFieldResult;
	private String saveTo = null;
	private String filename = null;
	private String extensionName = null;
	private String folderName = null;
	private JLabel labelLoading = null;
	private boolean isKeyUnlimitedVersion = false;
	private JButton buttonResult;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Frame1 window = new Frame1();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public Frame1() {
		initialize();
	}

	static void setFinalStatic(Field field, Object newValue) throws Exception {
		field.setAccessible(true);

		Field modifiersField = Field.class.getDeclaredField("modifiers");
		modifiersField.setAccessible(true);
		modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

		field.set(null, newValue);
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {

		int max;
		try {
			max = Cipher.getMaxAllowedKeyLength("AES");
			if (max > 128) {
				isKeyUnlimitedVersion = true;
			}
		} catch (NoSuchAlgorithmException e3) {
			// TODO Auto-generated catch block
			e3.printStackTrace();
		}

		try {
			// setFinalStatic(Boolean.class.getField("FALSE"), true);
		} catch (Exception e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}

		frame = new JFrame();
		frame.setBounds(100, 100, 530, 450);

		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		frame.setResizable(false);
		// ======Input Data Section=====
		// text field for data
		textFieldData = new JTextField();
		textFieldData.setEnabled(false);
		textFieldData.setBounds(164, 35, 202, 20);
		frame.getContentPane().add(textFieldData);
		textFieldData.setColumns(10);

		// label for data
		JLabel lblData = new JLabel("Data File (Hex)");
		lblData.setBounds(50, 38, 104, 14);
		frame.getContentPane().add(lblData);

		// label for data warning
		JLabel labelTextWarning = new JLabel("");
		labelTextWarning.setBounds(50, 63, 415, 14);
		frame.getContentPane().add(labelTextWarning);

		// button for brows the plaintext
		JButton buttonBrowseData = new JButton("Browse");
		buttonBrowseData.setBounds(376, 34, 89, 23);
		buttonBrowseData.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				labelTextWarning.setText("");
				JFileChooser chooser = new JFileChooser(new File(System.getProperty("user.home") + "\\Desktop"));
				// chooser.setCurrentDirectory(new java.io.File("."));
				chooser.setDialogTitle("Select file to process");
				chooser.setAcceptAllFileFilterUsed(false);

				if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					File dataFile = chooser.getSelectedFile();
					filename = dataFile.getName();

					String absPath = dataFile.getAbsolutePath();

					extensionName = filename.substring(filename.indexOf("."));
					System.out.println(extensionName);
					textFieldData.setText(absPath);

					try {
						// get byte from plaintext
						inputData = Files.readAllBytes(Paths.get(absPath));
						System.out.println(inputData.length);
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

					if (inputData != null && keyBytes != null) {
						buttonResult.setEnabled(true);
					} else {
						buttonResult.setEnabled(false);
					}

				} else {
					saveTo = "";
					System.out.println("No Selection ");
				}
			}
		});
		frame.getContentPane().add(buttonBrowseData);

		// ======Key Section=====

		// textfield for key
		textFieldKey = new JTextField();
		textFieldKey.setEnabled(false);
		textFieldKey.setBounds(164, 98, 202, 20);
		textFieldKey.setColumns(10);
		frame.getContentPane().add(textFieldKey);

		// label for key
		JLabel lblKey = new JLabel("Key File (Hex)");
		lblKey.setBounds(50, 101, 104, 14);
		frame.getContentPane().add(lblKey);

		// label for key warning
		JLabel labelKeyWarning = new JLabel("");
		labelKeyWarning.setBounds(50, 126, 415, 14);
		frame.getContentPane().add(labelKeyWarning);

		// button for browse the key
		JButton buttonBrowseKey = new JButton("Browse");
		buttonBrowseKey.setBounds(376, 97, 89, 23);
		buttonBrowseKey.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				labelKeyWarning.setText("");
				JFileChooser chooser = new JFileChooser(new File(System.getProperty("user.home") + "\\Desktop"));
				// chooser.setCurrentDirectory(new java.io.File("."));
				chooser.setDialogTitle("Select file to process");
				chooser.setAcceptAllFileFilterUsed(false);

				if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					File keyFile = chooser.getSelectedFile();

					String absPath = keyFile.getAbsolutePath();
					textFieldKey.setText(absPath);

					try {

						String stringInputKey = readFile(absPath);
						int keylength = stringInputKey.length();
						// JOptionPane.showMessageDialog(null, "Your java
						// version can't process key more than 128 bit. Please
						// install JCE Policy");
						if (keylength == 32 || keylength == 48 || keylength == 64) {
							if (keylength != 32 && !isKeyUnlimitedVersion) {
								JOptionPane.showMessageDialog(null,
										"Your java version can't process key more than 128 bit. Please install JCE Policy");
							} else {
								if (isHex(stringInputKey)) {
									System.out.println(stringInputKey);
									keyBytes = hexStringToByteArray(stringInputKey);
									System.out.println(Arrays.toString(keyBytes));
								} else {
									System.err.println(
											"AES key [" + stringInputKey + "] must be 32 or 48 or 64 hex digits long.");

								}
							}

						} else {
							labelKeyWarning.setText("Key must be 32 or 48 or 64 length in hex digit");
							labelKeyWarning.setForeground(Color.RED);
						}

						if (inputData != null && keyBytes != null) {
							buttonResult.setEnabled(true);
						} else {
							buttonResult.setEnabled(false);
						}

					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

				} else {
					saveTo = "";
					System.out.println("No Selection ");
				}

			}
		});
		frame.getContentPane().add(buttonBrowseKey);

		// ======Result Section=====

		JLabel lblResultFolder = new JLabel("Result Folder");
		lblResultFolder.setBounds(50, 163, 104, 14);
		frame.getContentPane().add(lblResultFolder);

		textFieldResult = new JTextField();
		textFieldResult.setEnabled(false);
		textFieldResult.setColumns(10);
		textFieldResult.setBounds(164, 160, 202, 20);
		frame.getContentPane().add(textFieldResult);

		JLabel labelResultWarning = new JLabel("");
		labelResultWarning.setBounds(50, 187, 415, 14);
		frame.getContentPane().add(labelResultWarning);

		buttonResult = new JButton("Browse");
		if (inputData != null && keyBytes != null) {
			buttonResult.setEnabled(true);
		} else {
			buttonResult.setEnabled(false);
		}

		buttonResult.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				labelResultWarning.setText("");
				FileDialog fDialog = new FileDialog(frame, "Save", FileDialog.SAVE);
				fDialog.setVisible(true);
				String absPath = fDialog.getDirectory() + fDialog.getFile();
				folderName = fDialog.getDirectory();
				// File f = new File(path);
				saveTo = absPath;
				if (saveTo != null) {
					textFieldResult.setText(saveTo);
				}

			}
		});
		buttonResult.setBounds(376, 159, 89, 23);
		frame.getContentPane().add(buttonResult);

		labelLoading = new JLabel("");
		labelLoading.setBounds(124, 201, 261, 14);
		labelLoading.setForeground(Color.GREEN);
		frame.getContentPane().add(labelLoading);

		// ====Encrypt Section====

		// button for encrypt
		JButton buttonEncrypt = new JButton("Encrpt");
		buttonEncrypt.setBounds(79, 237, 151, 43);
		buttonEncrypt.setForeground(Color.BLACK);
		buttonEncrypt.setBackground(Color.LIGHT_GRAY);
		buttonEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {

				saveTo += extensionName;
				labelTextWarning.setText("");
				labelKeyWarning.setText("");
				labelResultWarning.setText("");
				// make sure data and key is not null
				try {
					if (inputData != null && keyBytes != null && !textFieldResult.getText().equals("")) {
						System.out.println("masuk ini");
						labelLoading.setText("Please wait unitl the process is finished");

						encrypt(keyBytes, ivBytes, inputData);
					} else {
						if (inputData == null) {
							labelTextWarning.setForeground(Color.RED);
							labelTextWarning.setText("" + "Please input the data");
							textFieldData.setText("");
						}
						if (keyBytes == null) {
							labelKeyWarning.setForeground(Color.RED);
							labelKeyWarning.setText("Please input the key");
							textFieldKey.setText("");
						}
						if (textFieldResult.getText().equals("")) {
							labelResultWarning.setForeground(Color.RED);
							labelResultWarning.setText("Please input destination folder");
							textFieldResult.setText("");
						}
					}

				} catch (OutOfMemoryError e0) {
					JOptionPane.showMessageDialog(null, "Out of Memmory Eror. The file is too big ");

				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

			}
		});
		frame.getContentPane().add(buttonEncrypt);

		//// ======Decrypt Section=====
		JButton buttonDecrypt = new JButton("Decrypt");
		buttonDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				saveTo += extensionName;
				labelTextWarning.setText("");
				labelKeyWarning.setText("");
				labelResultWarning.setText("");
				try {
					if (inputData != null && keyBytes != null && !textFieldResult.getText().equals("")) {
						labelLoading.setText("Please wait unitl the process is finished");

						decrypt(keyBytes, ivBytes, inputData);
					} else {
						if (inputData == null) {
							labelTextWarning.setForeground(Color.RED);
							labelTextWarning.setText("Please input the data");
							textFieldData.setText("");
						}
						if (keyBytes == null) {
							labelKeyWarning.setForeground(Color.RED);
							labelKeyWarning.setText("Please input the key");
							textFieldKey.setText("");
						}
						if (textFieldResult.getText().equals("")) {
							labelResultWarning.setForeground(Color.RED);
							labelResultWarning.setText("Please input destination folder");
							textFieldResult.setText("");
						}
					}

				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		buttonDecrypt.setForeground(Color.BLACK);
		buttonDecrypt.setBackground(Color.LIGHT_GRAY);
		buttonDecrypt.setBounds(268, 237, 151, 43);
		frame.getContentPane().add(buttonDecrypt);

		// ======Open Result Section=====
		JButton buttonOpenResult = new JButton("Open in Explorer");
		buttonOpenResult.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					if(folderName!=null){
						Desktop.getDesktop().open(new File(folderName));	
					}else{
						JOptionPane.showMessageDialog(null, "Do the encryption/decryption first");
					}
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		buttonOpenResult.setForeground(Color.BLACK);
		buttonOpenResult.setBackground(Color.LIGHT_GRAY);
		buttonOpenResult.setBounds(174, 306, 151, 43);
		frame.getContentPane().add(buttonOpenResult);

	}

	public void encrypt(byte[] keyBytes, byte[] ivBytes, byte[] plainText) throws Exception {
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");

		cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
		ByteArrayInputStream bIn = new ByteArrayInputStream(plainText);
		CipherInputStream cIn = new CipherInputStream(bIn, cipher);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		int ch;
		while ((ch = cIn.read()) >= 0) {
			bOut.write(ch);
		}

		cIn.close();

		byte[] cipherText = bOut.toByteArray();

		FileOutputStream fos = new FileOutputStream(saveTo);
		fos.write(cipherText);
		fos.close();

		labelLoading.setText("");
		JOptionPane.showMessageDialog(null, "Finished!");
		System.out.println("encrypt selesai");

	}

	public void decrypt(byte[] keyBytes, byte[] ivBytes, byte[] inputData) throws Exception {
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");

		cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);

		byte[] cipherText = inputData;
		cOut.write(cipherText);
		cOut.close();
		// System.out.println("plain: " + new String(bOut.toByteArray()));

		FileOutputStream fos2 = new FileOutputStream(saveTo);
		fos2.write(bOut.toByteArray());
		fos2.close();

		labelLoading.setText("");
		JOptionPane.showMessageDialog(null, "Finished!");
		System.out.println("decrypt selesai");
	}

	// http://stackoverflow.com/questions/16027229/reading-from-a-text-file-and-storing-in-a-string
	public static String readFile(String fileName) throws IOException {
		BufferedReader br = new BufferedReader(new FileReader(fileName));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				line = br.readLine();
			}
			return sb.toString();
		} finally {
			br.close();
		}
	}

	// method to make key input as hex-to-4bit
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	// method to validate if the content of key file is hex
	public static boolean isHex(String hex) {
		int len = hex.length();
		int i = 0;
		char ch;

		while (i < len) {
			ch = hex.charAt(i++);
			System.out.println("ch" + ch);
			if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f')))
				return false;
		}
		return true;
	}
}
