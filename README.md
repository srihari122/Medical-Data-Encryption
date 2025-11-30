MEDICAL DATA ENCRYPTION WEB APPLICATION
 Medical image such as MRI, CT scan reports should be kept securely. Patients privacy should be considered. 
More Number of data breaches are occurring in health care systems. Many traditional 
encryption methods do not provide more security to the data. In this project we have used SM4 
technique that allow addition safe keeping of the patient’s data. We have developed different 
Modules of admin, patient, encryption, decryption, transfer module. 
UI:
ADMIN lOGIN PAGE
<img width="955" height="443" alt="Admin login" src="https://github.com/user-attachments/assets/bbb91d95-fac1-4b33-8efd-5f2e4bd35fa7" />

PATIENT LOGIN
![Patientlogin](https://github.com/user-attachments/assets/4c7f9c88-2993-4590-b7df-352ee1892266)


<img width="320" height="393" alt="imagedecrytion" src="https://github.com/user-attachments/assets/824c5a2a-b1d1-49fb-96b1-fcb37bb27778" />

![imageencryptioninsideanotherImage](https://github.com/user-attachments/assets/19a00d5c-96be-4dab-a8cc-a84039f53e48)


![textencryptinsideimage](https://github.com/user-attachments/assets/10b74404-6ff7-4825-a9a7-02cf41f4f6f4)

<img width="403" height="366" alt="textdecryptionfromimage" src="https://github.com/user-attachments/assets/05998b63-267a-4fe4-a1e7-32e6dc8c1ebe" />


ADMIN:
These are the individuals who generate or access medical images (like MRI, CT scans, and X
rays) for diagnosis and treatment. Responsible for managing the encryption and decryption 
keys, ensuring that the system operates securely. The healthcare provider selects a medical 
image (such as MRI, CT scans, or X-rays) to encrypt using the SM4 algorithm. This ensures 
the image is safeguarded during transmission or storage. After the image is encrypted, the 
healthcare provider can decrypt it using the corresponding key to access the original, 
intelligible medical image for diagnosis and treatment. The healthcare provider 
can request access to encrypted images but will need the proper decryption key to view them.

PATIENT:
Represents the end-user of the system. They will be registered by the hospital admin by 
collecting information of patients. They should enter their details when they want to retrieve the 
information. Interacts with the system by uploading key and downloading encrypted or 
decrypted images. Patient is not directly involved but the entity whose data is protected. They 
would be the indirect beneficiary of the encrypted data being securely handled.
