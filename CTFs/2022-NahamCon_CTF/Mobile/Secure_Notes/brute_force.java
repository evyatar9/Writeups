public class Main {

	public static void main(String[] args) throws IOException {
	
		for(int i = 1000 ; i<10000 ; i++)
		{
			
			String iStr = String.valueOf(i);
			String currentPin = iStr + iStr + iStr + iStr;
			
			 try {
				File file = new File("/mobile/secure_notes/db.encrypted");
				File file2= new File("/mobile/secure_notes/notes.db");
				 
		            SecretKeySpec secretKeySpec = new SecretKeySpec(currentPin.getBytes(), "AES");
		            Cipher instance = Cipher.getInstance("AES");
		            instance.init(2, secretKeySpec);
		            FileInputStream fileInputStream = new FileInputStream(file);
		            byte[] bArr = new byte[(int) file.length()];
		            fileInputStream.read(bArr);
		            byte[] doFinal = instance.doFinal(bArr);
		            FileOutputStream fileOutputStream = new FileOutputStream(file2);
		            fileOutputStream.write(doFinal);
		            fileInputStream.close();
		            fileOutputStream.close();

		            String content = Files.readString(Paths.get("/mobile/secure_notes/notes.db"), StandardCharsets.US_ASCII);
		            if(content.contains("notes"))
		            {
		            	System.out.println("The PIN code is: " + i);
		            	break;
		            }
		            break;
		        } catch (Exception e2) {
		        	
		        }
		}
	}
}