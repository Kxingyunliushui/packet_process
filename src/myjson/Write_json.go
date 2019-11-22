package myjson

import (
	"encoding/json"
	"fmt"
	"os"
)

type Vidata struct {
	State0 string `json:"state0, string"`
	State1 string `json:"state1, string"`
	Time   string `json:"time, string"`
	Time0  string `json:"time0, string"`
	Ip     string `json:"ip, string"`
	Mac    string `json:"mac, string"`
	Url    string `json:"url, string"`
	Ua     string `json:"ua, string"`
	//Reffer string `json:"reffer, string"`
	//Cookie string `json:"cookie, string"`
}

func Write(tmpdate Vidata, file_fd *os.File)  {
	b, err := json.Marshal(tmpdate)
	if err != nil {
		fmt.Println("Error:",err)
	}


	//file_fd, err := os.Open(filename)
	//if err != nil {
	//	fmt.Printf("Cannot open file %s!\n", "filename")
	//	return
	//}
	//defer file_fd.Close()

	//err = ioutil.WriteFile("test.json", b, os.ModeAppend)
	_,err =file_fd.Write(b)
	if err != nil {
		fmt.Println("Error",err)
		return
	}
	_,err =file_fd.WriteString("\n")

}
