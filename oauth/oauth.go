package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kadekchrisna/openbook-oauth-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClient   = "X-Client"
	headerXCallerId = "X-User-Id"

	paramsAccessToken = "access_token"
)

type (
	accessToken struct {
		Id       string `json:"id"`
		UserId   int64  `json:"user_id"`
		ClientId int64  `json:"client_id"`
	}
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClient), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.ResErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessToken := strings.TrimSpace(request.URL.Query().Get(paramsAccessToken))
	if accessToken == "" {
		return nil
	}

	at, err := getAccessToken(accessToken)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXClient, fmt.Sprintf("%v", at.ClientId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClient)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenReq string) (*accessToken, *errors.ResErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/access-token/gen/%s", accessTokenReq))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("Invalid client to login user")
	}
	if response.StatusCode > 299 {
		var errRes errors.ResErr
		if err := json.Unmarshal(response.Bytes(), &errRes); err != nil {
			return nil, errors.NewInternalServerError("Invalid error interface at login user")
		}
		return nil, &errRes
	}

	var at accessToken
	fmt.Println(string(response.Bytes()))
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("Invalid user interface at login user")
	}
	return &at, nil

}
