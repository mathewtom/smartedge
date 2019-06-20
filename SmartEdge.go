package main

import (
	"fmt"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"bufio"
	"io/ioutil"
	"encoding/pem"
)

//Defining a type that will be used to MarshalJSon in the main function.
type jsonobj struct {
	Message string
	Signature string
	Pubkey string
	}

//This function will check to see if a PrivateKey exists on the filesystem or will generate a new private key.
//New or existing keys are stored on the filesystem as Pem Encoded X509 format in a txt file.
func genKeys() (privateKey *ecdsa.PrivateKey){

	//Check to see if a keyfile.txt exists on the file system.
	if _, err := os.Stat("keyfile.txt"); err == nil {
  	fmt.Println("Using exists keys found on the filesystem! \n")
	
	//Read the existing PemEncoded private key from the txt file.	
	keyfile, err := ioutil.ReadFile("keyfile.txt")
	 		if err != nil {
 			fmt.Println(err)
 			}

	//Use a decode function to decode the Pem Encoded x509 formatted private key.
	privateKey := decode(string(keyfile))
	
	return privateKey

	} else { 
		//Else Generate/return a new private key and store it on the filesystem for future use.
		fmt.Println("Keys not found on filesystem. Generating new keys! \n") 
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
			panic(err)
			}
		
		//x509 format and Pem encode the private key for easy filesystem storage/retrieval.
		privKeyPemEncoded := encode(privateKey) 

		//write the new private key into a txt file
		file, err := os.OpenFile("keyfile.txt", os.O_WRONLY|os.O_CREATE, 0666)
    			if err != nil {
        		fmt.Println("File cannot be created")
        		os.Exit(1)
    			}
   		defer file.Close()
		w := bufio.NewWriter(file)
		fmt.Fprintf(w,privKeyPemEncoded)
		w.Flush()

		return privateKey
		}
	}

//This function will convert the Private Key into x509 format and then Pem encode it.
func encode(privateKey *ecdsa.PrivateKey) (string) {
    x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

    return string(pemEncoded)
}

//This function will decode the private key from a Pem encoded x509 format.
func decode(pemEncoded string) (*ecdsa.PrivateKey) {
    block, _ := pem.Decode([]byte(pemEncoded))
    x509Encoded := block.Bytes
    privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

    return privateKey
}


func main() {

	//Check to see if a string input of less than 250 characters is provided by the user.
	if (len(os.Args) < 2 || len(os.Args[1]) > 250) {
	fmt.Println("Please enter a string (preferably email) between 1 and 250 characters")
	} else {
		
		input_var := os.Args[1]
	
		//Generate ECDSA private key.
		privateKey := genKeys()
	
		//Generate the Public key from the Private Key.
		pubz := privateKey.Public()
	
		//Generate sha256 hash of the user input.
		hash := sha256.Sum256([]byte(input_var))
	
		//Generate signature of the sha256 hash of the input using the private key.
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
			if err != nil {
				panic(err)
			}
			
		//Base64 encode the signature in compliance with RFC4648.
		//The signature needs to be changed from type big_int to string in order to be Base64 encoded.
		r_bigstr := r.String()
		s_bigstr := s.String()
		str_64 := r_bigstr + ", " + s_bigstr
		encoded := base64.StdEncoding.EncodeToString([]byte(str_64))
	
		//Converting the public key into type string
		pubz_bigstr := fmt.Sprint(pubz)
	
		//Pem encode the public key.
		block := &pem.Block{
		Type: "Public Key",
		Bytes: []byte(pubz_bigstr),
		}
		blockencode := string(pem.EncodeToMemory(block)) 
	
		//Use Json to output the user input, signature and public key.
		group := jsonobj {
			Message: input_var,
			Signature: encoded,
			Pubkey: blockencode,
			}
	
		bent, _:= json.MarshalIndent(group, " ", " ")
	
		os.Stdout.Write(bent)
		fmt.Println("\n")		
		}
}