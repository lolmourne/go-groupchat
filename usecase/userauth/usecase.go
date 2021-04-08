package userauth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/lolmourne/go-groupchat/model"
)

func (u *Usecase) GetUserInfo(accessToken string) *model.User {
	client := &http.Client{
		Timeout: u.timeout,
	}

	req, err := http.NewRequest("GET", u.endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Access-Token", accessToken)

	respRaw, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer respRaw.Body.Close()

	if err != nil {
		return nil
	}

	if respRaw.StatusCode != 200 {
		return nil
	}

	respByte, err := ioutil.ReadAll(respRaw.Body)
	if err != nil {
		log.Print(err)
		return nil
	}

	var resp struct {
		Err  string     `json:"err"`
		Data model.User `json:"data"`
	}

	err = json.Unmarshal(respByte, &resp)
	if err != nil {
		return nil
	}

	return &resp.Data
}
