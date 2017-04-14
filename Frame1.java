import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.awt.event.ActionEvent;
import java.awt.Color;
import java.awt.Desktop;

import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JTextPane;

public class Frame1 {

	private JFrame frame;
	private JTextField textFieldData;
	private JTextField textFieldKey;
	// set iv static as counter
	private byte[] ivBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00 };
	// set default ket
	// byte[] keyBytesDefault = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	// 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	// 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	// setdefaultplaintext
	// byte[] plainTextDefault = "default".getBytes();
	// key
	byte[] keyBytes = null;
	// plaintext
	byte[] inputData = null;
	private JTextField textFieldResult;
	private String saveTo= null;
	private String filename=null;

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

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		// frame
		frame = new JFrame();
		frame.setBounds(100, 100, 530, 450);
		
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(null);
		frame.setResizable(false);
		// ======Input Data Section=====
		// text field for data
		textFieldData = new JTextField();
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
				JFileChooser chooser = new JFileChooser(new File(System.getProperty("user.home") + "\\Desktop"));
				// chooser.setCurrentDirectory(new java.io.File("."));
				chooser.setDialogTitle("Select file to process");
				chooser.setAcceptAllFileFilterUsed(false);

				if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					File dataFile = chooser.getSelectedFile();
					filename=dataFile.getName();
					String absPath = dataFile.getAbsolutePath();
					textFieldData.setText(absPath);

					try {
						// get byte from plaintext
						inputData = Files.readAllBytes(Paths.get(absPath));

					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

				} else {
					System.out.println("No Selection ");
				}
			}
		});
		frame.getContentPane().add(buttonBrowseData);
		
		// ======Key Section=====
		
		// textfield for key
		textFieldKey = new JTextField();
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
						if (keylength == 32 || keylength == 48 || keylength == 64) {
							if (isHex(stringInputKey)) {
								System.out.println(stringInputKey);
								keyBytes = hexStringToByteArray(stringInputKey);
							} else {
								System.err.println(
										"AES key [" + stringInputKey + "] must be 32 or 48 or 64 hex digits long.");

							}
						} else {
							labelKeyWarning.setText("Key must be 32 or 48 or 64 length in hex digit");
							labelKeyWarning.setForeground(Color.RED);
						}

					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}

				} else {
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
		textFieldResult.setColumns(10);
		textFieldResult.setBounds(164, 160, 202, 20);
		frame.getContentPane().add(textFieldResult);

		JButton buttonResult = new JButton("Browse");
		buttonResult.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				
				JFileChooser chooser = new JFileChooser();
				// chooser.setCurrentDirectory(new java.io.File("."));
				chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				chooser.setDialogTitle("Select file to process");
				chooser.setAcceptAllFileFilterUsed(false);

				if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					
					File filePath = chooser.getSelectedFile();
					String absPath = filePath.getAbsolutePath();
					textFieldResult.setText(absPath);
					saveTo = absPath;
				} else {
					System.out.println("No Selection ");
				}

			}
		});
		buttonResult.setBounds(376, 159, 89, 23);
		frame.getContentPane().add(buttonResult);

		JLabel labelResultWarning = new JLabel("");
		labelResultWarning.setBounds(50, 187, 415, 14);
		frame.getContentPane().add(labelResultWarning);
		
		//====Encrypt Section====
		
		// button for encrypt
		JButton buttonEncrypt = new JButton("Encrpt");
		buttonEncrypt.setBounds(79, 237, 151, 43);
		buttonEncrypt.setForeground(Color.BLACK);
		buttonEncrypt.setBackground(Color.LIGHT_GRAY);
		buttonEncrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				labelTextWarning.setText("");
				labelKeyWarning.setText("");

				// make sure data and key is not null
				try {
					if (inputData != null && keyBytes != null) {
						encrypt(keyBytes, ivBytes, inputData);
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
						if(saveTo==null){
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
		frame.getContentPane().add(buttonEncrypt);
		
		//// ======Decrypt Section=====
		JButton buttonDecrypt = new JButton("Decrypt");
		buttonDecrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				labelTextWarning.setText("");
				labelKeyWarning.setText("");
				try {
					if (inputData != null && keyBytes != null) {
						decrypt(keyBytes, ivBytes);
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
						if(saveTo==null){
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
					Desktop.getDesktop().open(new File(saveTo));
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

		byte[] cipherText = bOut.toByteArray();

		FileOutputStream fos = new FileOutputStream(saveTo+"\\encrypted"+filename);
		fos.write(cipherText);
		fos.close();

		System.out.println("encrypt selesai");

	}

	public void decrypt(byte[] keyBytes, byte[] ivBytes) throws Exception {
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

		FileOutputStream fos2 = new FileOutputStream(saveTo+"\\decrypted"+filename);
		fos2.write(bOut.toByteArray());
		fos2.close();

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
