package backenfitness

import (
	json2 "encoding/json"
	"net/http"
	"os"

	"github.com/whatsauth/watoken"
)

func GetDataUserFromGCF(PublicKey, MongoEnv, dbname, colname string, r *http.Request) string {
	req := new(ResponseDataUser)
	conn := MongoCreateConnection(MongoEnv, dbname)
	cihuy := new(Response)
	err := json2.NewDecoder(r.Body).Decode(&cihuy)
	if err != nil {
		req.Status = false
		req.Message = "error parsing application/json: " + err.Error()
	} else {
		checktoken, err := watoken.DecodeGetId(os.Getenv(PublicKey), cihuy.Token)
		if err != nil {
			req.Status = false
			req.Message = "Token decoding error: " + err.Error()
			return ReturnStringStruct(req)
		}

		compared := CompareUsername(conn, colname, checktoken)
		if compared != true {
			req.Status = false
			req.Message = "Data Username tidak ada di database"
		} else {
			datauser := GetAllUser(conn, colname)
			req.Status = true
			req.Message = "data User berhasil diambil"
			req.Data = datauser
		}
	}
	return ReturnStringStruct(req)
}

func ReturnStringStruct(Data any) string {
	json, _ := json2.Marshal(Data)
	return string(json)
}

func GCFPasetoTokenStr(PrivateKey, MongoEnv, dbname, collectionname string, r *http.Request) string {
	var resp Credential
	resp.Status = false
	mconn := MongoCreateConnection(MongoEnv, dbname)
	var datauser User
	err := json2.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		if PasswordValidator(mconn, collectionname, datauser) {
			resp.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PrivateKey))
			if err != nil {
				resp.Message = "Gagal Encode Token : " + err.Error()
			} else {
				resp.Message = "Selamat Datang"
				resp.Token = tokenstring
			}
		} else {
			resp.Message = "Password Salah"
		}
	}

	return ReturnStringStruct(resp)
}

func GCFPasswordHasher(r *http.Request) string {
	resp := new(Credential)
	userdata := new(User)
	resp.Status = false
	err := json2.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		passwordhash, err := HashPass(userdata.Password)
		if err != nil {
			resp.Message = "Gagal Hash Passwordnya : " + err.Error()
		} else {
			resp.Status = true
			resp.Message = "Berhasil Hash Password"
			resp.Token = passwordhash
		}
	}
	return ReturnStringStruct(resp)
}

func InsertDataUserGCF(Mongoenv, dbname string, r *http.Request) string {
	resp := new(Credential)
	userdata := new(User)
	resp.Status = false
	conn := MongoCreateConnection(Mongoenv, dbname)
	err := json2.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		resp.Status = true
		hash, err := HashPass(userdata.Password)
		if err != nil {
			resp.Message = "Gagal Hash Password" + err.Error()
		}
		userdata.Password = hash
		InsertUserdata(conn, *userdata)
		resp.Message = "Berhasil Input data"
	}
	return ReturnStringStruct(resp)
}
