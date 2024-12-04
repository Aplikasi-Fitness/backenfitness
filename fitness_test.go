package backenfitness

import (
	"fmt"
	"testing"

	"github.com/whatsauth/watoken"
)

var privatekey = "privatekey"
var publickeyb = "publickey"
var encode = "encode"

func TestGenerateKeyPASETO(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("asoy", privateKey)
	fmt.Println(hasil, err)
}

func TestHashPass(t *testing.T) {
	password := "cihuypass"

	Hashedpass, err := HashPass(password)
	fmt.Println("error : ", err)
	fmt.Println("Hash : ", Hashedpass)
}

func TestHashFunc(t *testing.T) {
	conn := MongoCreateConnection("MONGOSTRING", "Fitness")
	userdata := new(User)
	userdata.Username = "cihuy"
	userdata.Password = "cihuypass"

	data := GetOneUser(conn, "user", User{
		Username: userdata.Username,
		Password: userdata.Password,
	})
	fmt.Printf("%+v", data)
	fmt.Println(" ")
	hashpass, _ := HashPass(userdata.Password)
	fmt.Println("Hasil hash : ", hashpass)
	compared := CompareHashPass(userdata.Password, data.Password)
	fmt.Println("result : ", compared)
}

func TestTokenEncoder(t *testing.T) {
	conn := MongoCreateConnection("MONGOSTR", "Fitness")
	privateKey, publicKey := watoken.GenerateKey()
	userdata := new(User)
	userdata.Username = "cihuy"
	userdata.Password = "cihuypass"

	data := GetOneUser(conn, "user", User{
		Username: userdata.Username,
		Password: userdata.Password,
	})
	fmt.Println("Private Key : ", privateKey)
	fmt.Println("Public Key : ", publicKey)
	fmt.Printf("%+v", data)
	fmt.Println(" ")

	encode := TokenEncoder(data.Username, privateKey)
	fmt.Printf("%+v", encode)
}

func TestInsertUserdata(t *testing.T) {
	// Membuat koneksi ke database MongoDB
	conn := MongoCreateConnection("MONGOSTRING", "Fitness")

	// Hashing password
	password, err := HashPass("rijik123")
	if err != nil {
		t.Fatalf("Error hashing password: %v", err) // Jika ada error hashing password, gagalkan test
	}

	// Membuat objek User
	user := User{
		Username: "rijik",
		Password: password,
		Role:     "user",
		Email:    "rijik@gmail.com",
	}

	// Memasukkan data user ke database
	data := InsertUserdata(conn, user)

	// Menampilkan hasil data yang dimasukkan
	fmt.Println(data)
}

func TestDecodeToken(t *testing.T) {
	id, err := watoken.DecodeGetId("public", "token")
	if err != nil {
		t.Errorf("DecodeGetId error: %v", err)
		return
	}
	fmt.Println(id)
}

func TestCompareUsername(t *testing.T) {
	// Membuat koneksi ke MongoDB
	conn := MongoCreateConnection("MONGOSTRING", "Fitness")

	// Decode token, tangkap kedua nilai (ID dan error)
	id, err := watoken.DecodeGetId("public", "token")
	if err != nil {
		t.Fatalf("Error decoding token: %v", err) // Jika ada error decoding, test gagal
	}

	// Bandingkan username dengan ID yang ter-decode
	compare := CompareUsername(conn, "user", id)
	fmt.Println(compare)
}

func TestEncodeWithRole(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	role := "admin"
	username := "cihuy"
	encoder, err := EncodeWithRole(role, username, privateKey)

	fmt.Println(" error :", err)
	fmt.Println("Private :", privateKey)
	fmt.Println("Public :", publicKey)
	fmt.Println("encode: ", encoder)

}

func TestDecoder2(t *testing.T) {
	pay, err := Decoder(publickeyb, encode)
	user, _ := DecodeGetUser(publickeyb, encode)
	role, _ := DecodeGetRole(publickeyb, encode)
	use, ro := DecodeGetRoleandUser(publickeyb, encode)
	fmt.Println("user :", user)
	fmt.Println("role :", role)
	fmt.Println("user and role :", use, ro)
	fmt.Println("err : ", err)
	fmt.Println("payload : ", pay)
}
