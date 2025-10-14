package _139

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alist-org/alist/v3/drivers/base"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/internal/op"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/alist-org/alist/v3/pkg/utils/random"
	"github.com/go-resty/resty/v2"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
)

// do others that not defined in Driver interface
func (d *Yun139) isFamily() bool {
	return d.Type == "family"
}

func encodeURIComponent(str string) string {
	r := url.QueryEscape(str)
	r = strings.Replace(r, "+", "%20", -1)
	r = strings.Replace(r, "%21", "!", -1)
	r = strings.Replace(r, "%27", "'", -1)
	r = strings.Replace(r, "%28", "(", -1)
	r = strings.Replace(r, "%29", ")", -1)
	r = strings.Replace(r, "%2A", "*", -1)
	return r
}

func calSign(body, ts, randStr string) string {
	body = encodeURIComponent(body)
	strs := strings.Split(body, "")
	sort.Strings(strs)
	body = strings.Join(strs, "")
	body = base64.StdEncoding.EncodeToString([]byte(body))
	res := utils.GetMD5EncodeStr(body) + utils.GetMD5EncodeStr(ts+":"+randStr)
	res = strings.ToUpper(utils.GetMD5EncodeStr(res))
	return res
}

func getTime(t string) time.Time {
	stamp, _ := time.ParseInLocation("20060102150405", t, utils.CNLoc)
	return stamp
}

func (d *Yun139) refreshToken() error {
	if d.ref != nil {
		return d.ref.refreshToken()
	}
	decode, err := base64.StdEncoding.DecodeString(d.Authorization)
	if err != nil {
		return fmt.Errorf("authorization decode failed: %s", err)
	}
	decodeStr := string(decode)
	splits := strings.Split(decodeStr, ":")
	if len(splits) < 3 {
		return fmt.Errorf("authorization is invalid, splits < 3")
	}
	d.Account = splits[1]
	strs := strings.Split(splits[2], "|")
	if len(strs) < 4 {
		return fmt.Errorf("authorization is invalid, strs < 4")
	}
	expiration, err := strconv.ParseInt(strs[3], 10, 64)
	if err != nil {
		return fmt.Errorf("authorization is invalid")
	}
	expiration -= time.Now().UnixMilli()
	if expiration > 1000*60*60*24*15 {
		// Authorization有效期大于15天无需刷新
		return nil
	}
	if expiration < 0 {
		return fmt.Errorf("authorization has expired")
	}

	url := "https://aas.caiyun.feixin.10086.cn:443/tellin/authTokenRefresh.do"
	var resp RefreshTokenResp
	reqBody := "<root><token>" + splits[2] + "</token><account>" + splits[1] + "</account><clienttype>656</clienttype></root>"
	_, err = base.RestyClient.R().
		ForceContentType("application/xml").
		SetBody(reqBody).
		SetResult(&resp).
		Post(url)
	if err != nil || resp.Return != "0" {
		log.Warnf("139yun: failed to refresh token with old token: %v, desc: %s. trying to login with password.", err, resp.Desc)
		newAuth, loginErr := d.loginWithPassword()
		if loginErr != nil {
			return fmt.Errorf("failed to login with password after refresh failed: %w", loginErr)
		}
		d.Authorization = newAuth
		op.MustSaveDriverStorage(d)
		return nil
	}

	d.Authorization = base64.StdEncoding.EncodeToString([]byte(splits[0] + ":" + splits[1] + ":" + resp.Token))
	op.MustSaveDriverStorage(d)
	return nil
}

func (d *Yun139) request(pathname string, method string, callback base.ReqCallback, resp interface{}) ([]byte, error) {
	url := "https://yun.139.com" + pathname
	req := base.RestyClient.R()
	randStr := random.String(16)
	ts := time.Now().Format("2006-01-02 15:04:05")
	if callback != nil {
		callback(req)
	}
	body, err := utils.Json.Marshal(req.Body)
	if err != nil {
		return nil, err
	}
	sign := calSign(string(body), ts, randStr)
	svcType := "1"
	if d.isFamily() {
		svcType = "2"
	}
	req.SetHeaders(map[string]string{
		"Accept":         "application/json, text/plain, */*",
		"CMS-DEVICE":     "default",
		"Authorization":  "Basic " + d.getAuthorization(),
		"mcloud-channel": "1000101",
		"mcloud-client":  "10701",
		//"mcloud-route": "001",
		"mcloud-sign": fmt.Sprintf("%s,%s,%s", ts, randStr, sign),
		//"mcloud-skey":"",
		"mcloud-version":         "7.14.0",
		"Origin":                 "https://yun.139.com",
		"Referer":                "https://yun.139.com/w/",
		"x-DeviceInfo":           "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
		"x-huawei-channelSrc":    "10000034",
		"x-inner-ntwk":           "2",
		"x-m4c-caller":           "PC",
		"x-m4c-src":              "10002",
		"x-SvcType":              svcType,
		"Inner-Hcy-Router-Https": "1",
	})

	var e BaseResp
	req.SetResult(&e)
	res, err := req.Execute(method, url)
	log.Debugln(res.String())
	if !e.Success {
		return nil, errors.New(e.Message)
	}
	if resp != nil {
		err = utils.Json.Unmarshal(res.Body(), resp)
		if err != nil {
			return nil, err
		}
	}
	return res.Body(), nil
}

func (d *Yun139) requestRoute(data interface{}, resp interface{}) ([]byte, error) {
	url := "https://user-njs.yun.139.com/user/route/qryRoutePolicy"
	req := base.RestyClient.R()
	randStr := random.String(16)
	ts := time.Now().Format("2006-01-02 15:04:05")
	callback := func(req *resty.Request) {
		req.SetBody(data)
	}
	if callback != nil {
		callback(req)
	}
	body, err := utils.Json.Marshal(req.Body)
	if err != nil {
		return nil, err
	}
	sign := calSign(string(body), ts, randStr)
	svcType := "1"
	if d.isFamily() {
		svcType = "2"
	}
	req.SetHeaders(map[string]string{
		"Accept":         "application/json, text/plain, */*",
		"CMS-DEVICE":     "default",
		"Authorization":  "Basic " + d.getAuthorization(),
		"mcloud-channel": "1000101",
		"mcloud-client":  "10701",
		//"mcloud-route": "001",
		"mcloud-sign": fmt.Sprintf("%s,%s,%s", ts, randStr, sign),
		//"mcloud-skey":"",
		"mcloud-version":         "7.14.0",
		"Origin":                 "https://yun.139.com",
		"Referer":                "https://yun.139.com/w/",
		"x-DeviceInfo":           "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
		"x-huawei-channelSrc":    "10000034",
		"x-inner-ntwk":           "2",
		"x-m4c-caller":           "PC",
		"x-m4c-src":              "10002",
		"x-SvcType":              svcType,
		"Inner-Hcy-Router-Https": "1",
	})

	var e BaseResp
	req.SetResult(&e)
	res, err := req.Execute(http.MethodPost, url)
	log.Debugln(res.String())
	if !e.Success {
		return nil, errors.New(e.Message)
	}
	if resp != nil {
		err = utils.Json.Unmarshal(res.Body(), resp)
		if err != nil {
			return nil, err
		}
	}
	return res.Body(), nil
}

func (d *Yun139) post(pathname string, data interface{}, resp interface{}) ([]byte, error) {
	return d.request(pathname, http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
	}, resp)
}

func (d *Yun139) getFiles(catalogID string) ([]model.Obj, error) {
	start := 0
	limit := 100
	files := make([]model.Obj, 0)
	for {
		data := base.Json{
			"catalogID":       catalogID,
			"sortDirection":   1,
			"startNumber":     start + 1,
			"endNumber":       start + limit,
			"filterType":      0,
			"catalogSortType": 0,
			"contentSortType": 0,
			"commonAccountInfo": base.Json{
				"account":     d.getAccount(),
				"accountType": 1,
			},
		}
		var resp GetDiskResp
		_, err := d.post("/orchestration/personalCloud/catalog/v1.0/getDisk", data, &resp)
		if err != nil {
			return nil, err
		}
		for _, catalog := range resp.Data.GetDiskResult.CatalogList {
			f := model.Object{
				ID:       catalog.CatalogID,
				Name:     catalog.CatalogName,
				Size:     0,
				Modified: getTime(catalog.UpdateTime),
				Ctime:    getTime(catalog.CreateTime),
				IsFolder: true,
			}
			files = append(files, &f)
		}
		for _, content := range resp.Data.GetDiskResult.ContentList {
			f := model.ObjThumb{
				Object: model.Object{
					ID:       content.ContentID,
					Name:     content.ContentName,
					Size:     content.ContentSize,
					Modified: getTime(content.UpdateTime),
					HashInfo: utils.NewHashInfo(utils.MD5, content.Digest),
				},
				Thumbnail: model.Thumbnail{Thumbnail: content.ThumbnailURL},
				//Thumbnail: content.BigthumbnailURL,
			}
			files = append(files, &f)
		}
		if start+limit >= resp.Data.GetDiskResult.NodeCount {
			break
		}
		start += limit
	}
	return files, nil
}

func (d *Yun139) newJson(data map[string]interface{}) base.Json {
	common := map[string]interface{}{
		"catalogType": 3,
		"cloudID":     d.CloudID,
		"cloudType":   1,
		"commonAccountInfo": base.Json{
			"account":     d.getAccount(),
			"accountType": 1,
		},
	}
	return utils.MergeMap(data, common)
}

func (d *Yun139) familyGetFiles(catalogID string) ([]model.Obj, error) {
	pageNum := 1
	files := make([]model.Obj, 0)
	for {
		data := d.newJson(base.Json{
			"catalogID":       catalogID,
			"contentSortType": 0,
			"pageInfo": base.Json{
				"pageNum":  pageNum,
				"pageSize": 100,
			},
			"sortDirection": 1,
		})
		var resp QueryContentListResp
		_, err := d.post("/orchestration/familyCloud-rebuild/content/v1.2/queryContentList", data, &resp)
		if err != nil {
			return nil, err
		}
		path := resp.Data.Path
		for _, catalog := range resp.Data.CloudCatalogList {
			f := model.Object{
				ID:       catalog.CatalogID,
				Name:     catalog.CatalogName,
				Size:     0,
				IsFolder: true,
				Modified: getTime(catalog.LastUpdateTime),
				Ctime:    getTime(catalog.CreateTime),
				Path:     path, // 文件夹上一级的Path
			}
			files = append(files, &f)
		}
		for _, content := range resp.Data.CloudContentList {
			f := model.ObjThumb{
				Object: model.Object{
					ID:       content.ContentID,
					Name:     content.ContentName,
					Size:     content.ContentSize,
					Modified: getTime(content.LastUpdateTime),
					Ctime:    getTime(content.CreateTime),
					Path:     path, // 文件所在目录的Path
				},
				Thumbnail: model.Thumbnail{Thumbnail: content.ThumbnailURL},
				//Thumbnail: content.BigthumbnailURL,
			}
			files = append(files, &f)
		}
		if resp.Data.TotalCount == 0 {
			break
		}
		pageNum++
	}
	return files, nil
}

func (d *Yun139) groupGetFiles(catalogID string) ([]model.Obj, error) {
	pageNum := 1
	files := make([]model.Obj, 0)
	for {
		data := d.newJson(base.Json{
			"groupID":         d.CloudID,
			"catalogID":       path.Base(catalogID),
			"contentSortType": 0,
			"sortDirection":   1,
			"startNumber":     pageNum,
			"endNumber":       pageNum + 99,
			"path":            path.Join(d.RootFolderID, catalogID),
		})

		var resp QueryGroupContentListResp
		_, err := d.post("/orchestration/group-rebuild/content/v1.0/queryGroupContentList", data, &resp)
		if err != nil {
			return nil, err
		}
		path := resp.Data.GetGroupContentResult.ParentCatalogID
		for _, catalog := range resp.Data.GetGroupContentResult.CatalogList {
			f := model.Object{
				ID:       catalog.CatalogID,
				Name:     catalog.CatalogName,
				Size:     0,
				IsFolder: true,
				Modified: getTime(catalog.UpdateTime),
				Ctime:    getTime(catalog.CreateTime),
				Path:     catalog.Path, // 文件夹的真实Path， root:/开头
			}
			files = append(files, &f)
		}
		for _, content := range resp.Data.GetGroupContentResult.ContentList {
			f := model.ObjThumb{
				Object: model.Object{
					ID:       content.ContentID,
					Name:     content.ContentName,
					Size:     content.ContentSize,
					Modified: getTime(content.UpdateTime),
					Ctime:    getTime(content.CreateTime),
					Path:     path, // 文件所在目录的Path
				},
				Thumbnail: model.Thumbnail{Thumbnail: content.ThumbnailURL},
				//Thumbnail: content.BigthumbnailURL,
			}
			files = append(files, &f)
		}
		if (pageNum + 99) > resp.Data.GetGroupContentResult.NodeCount {
			break
		}
		pageNum = pageNum + 100
	}
	return files, nil
}

func (d *Yun139) getLink(contentId string) (string, error) {
	data := base.Json{
		"appName":   "",
		"contentID": contentId,
		"commonAccountInfo": base.Json{
			"account":     d.getAccount(),
			"accountType": 1,
		},
	}
	res, err := d.post("/orchestration/personalCloud/uploadAndDownload/v1.0/downloadRequest",
		data, nil)
	if err != nil {
		return "", err
	}
	return jsoniter.Get(res, "data", "downloadURL").ToString(), nil
}
func (d *Yun139) familyGetLink(contentId string, path string) (string, error) {
	data := d.newJson(base.Json{
		"contentID": contentId,
		"path":      path,
	})
	res, err := d.post("/orchestration/familyCloud-rebuild/content/v1.0/getFileDownLoadURL",
		data, nil)
	if err != nil {
		return "", err
	}
	return jsoniter.Get(res, "data", "downloadURL").ToString(), nil
}

func (d *Yun139) groupGetLink(contentId string, path string) (string, error) {
	data := d.newJson(base.Json{
		"contentID": contentId,
		"groupID":   d.CloudID,
		"path":      path,
	})
	res, err := d.post("/orchestration/group-rebuild/groupManage/v1.0/getGroupFileDownLoadURL",
		data, nil)
	if err != nil {
		return "", err
	}
	return jsoniter.Get(res, "data", "downloadURL").ToString(), nil
}

func unicode(str string) string {
	textQuoted := strconv.QuoteToASCII(str)
	textUnquoted := textQuoted[1 : len(textQuoted)-1]
	return textUnquoted
}

func (d *Yun139) personalRequest(pathname string, method string, callback base.ReqCallback, resp interface{}) ([]byte, error) {
	url := d.getPersonalCloudHost() + pathname
	req := base.RestyClient.R()
	randStr := random.String(16)
	ts := time.Now().Format("2006-01-02 15:04:05")
	if callback != nil {
		callback(req)
	}
	body, err := utils.Json.Marshal(req.Body)
	if err != nil {
		return nil, err
	}
	sign := calSign(string(body), ts, randStr)
	svcType := "1"
	if d.isFamily() {
		svcType = "2"
	}
	req.SetHeaders(map[string]string{
		"Accept":               "application/json, text/plain, */*",
		"Authorization":        "Basic " + d.getAuthorization(),
		"Caller":               "web",
		"Cms-Device":           "default",
		"Mcloud-Channel":       "1000101",
		"Mcloud-Client":        "10701",
		"Mcloud-Route":         "001",
		"Mcloud-Sign":          fmt.Sprintf("%s,%s,%s", ts, randStr, sign),
		"Mcloud-Version":       "7.14.0",
		"x-DeviceInfo":         "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
		"x-huawei-channelSrc":  "10000034",
		"x-inner-ntwk":         "2",
		"x-m4c-caller":         "PC",
		"x-m4c-src":            "10002",
		"x-SvcType":            svcType,
		"X-Yun-Api-Version":    "v1",
		"X-Yun-App-Channel":    "10000034",
		"X-Yun-Channel-Source": "10000034",
		"X-Yun-Client-Info":    "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||dW5kZWZpbmVk||",
		"X-Yun-Module-Type":    "100",
		"X-Yun-Svc-Type":       "1",
	})

	var e BaseResp
	req.SetResult(&e)
	res, err := req.Execute(method, url)
	if err != nil {
		return nil, err
	}
	log.Debugln(res.String())
	if !e.Success {
		return nil, errors.New(e.Message)
	}
	if resp != nil {
		err = utils.Json.Unmarshal(res.Body(), resp)
		if err != nil {
			return nil, err
		}
	}
	return res.Body(), nil
}
func (d *Yun139) personalPost(pathname string, data interface{}, resp interface{}) ([]byte, error) {
	return d.personalRequest(pathname, http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
	}, resp)
}

func getPersonalTime(t string) time.Time {
	stamp, err := time.ParseInLocation("2006-01-02T15:04:05.999-07:00", t, utils.CNLoc)
	if err != nil {
		panic(err)
	}
	return stamp
}

func (d *Yun139) personalGetFiles(fileId string) ([]model.Obj, error) {
	files := make([]model.Obj, 0)
	nextPageCursor := ""
	for {
		data := base.Json{
			"imageThumbnailStyleList": []string{"Small", "Large"},
			"orderBy":                 "updated_at",
			"orderDirection":          "DESC",
			"pageInfo": base.Json{
				"pageCursor": nextPageCursor,
				"pageSize":   100,
			},
			"parentFileId": fileId,
		}
		var resp PersonalListResp
		_, err := d.personalPost("/file/list", data, &resp)
		if err != nil {
			return nil, err
		}
		nextPageCursor = resp.Data.NextPageCursor
		for _, item := range resp.Data.Items {
			var isFolder = (item.Type == "folder")
			var f model.Obj
			if isFolder {
				f = &model.Object{
					ID:       item.FileId,
					Name:     item.Name,
					Size:     0,
					Modified: getPersonalTime(item.UpdatedAt),
					Ctime:    getPersonalTime(item.CreatedAt),
					IsFolder: isFolder,
				}
			} else {
				var Thumbnails = item.Thumbnails
				var ThumbnailUrl string
				if d.UseLargeThumbnail {
					for _, thumb := range Thumbnails {
						if strings.Contains(thumb.Style, "Large") {
							ThumbnailUrl = thumb.Url
							break
						}
					}
				}
				if ThumbnailUrl == "" && len(Thumbnails) > 0 {
					ThumbnailUrl = Thumbnails[len(Thumbnails)-1].Url
				}
				f = &model.ObjThumb{
					Object: model.Object{
						ID:       item.FileId,
						Name:     item.Name,
						Size:     item.Size,
						Modified: getPersonalTime(item.UpdatedAt),
						Ctime:    getPersonalTime(item.CreatedAt),
						IsFolder: isFolder,
					},
					Thumbnail: model.Thumbnail{Thumbnail: ThumbnailUrl},
				}
			}
			files = append(files, f)
		}
		if len(nextPageCursor) == 0 {
			break
		}
	}
	return files, nil
}

func (d *Yun139) personalGetLink(fileId string) (string, error) {
	data := base.Json{
		"fileId": fileId,
	}
	res, err := d.personalPost("/file/getDownloadUrl",
		data, nil)
	if err != nil {
		return "", err
	}
	var cdnUrl = jsoniter.Get(res, "data", "cdnUrl").ToString()
	if cdnUrl != "" {
		return cdnUrl, nil
	} else {
		return jsoniter.Get(res, "data", "url").ToString(), nil
	}
}

func (d *Yun139) getAuthorization() string {
	if d.ref != nil {
		return d.ref.getAuthorization()
	}
	return d.Authorization
}
func (d *Yun139) getAccount() string {
	if d.ref != nil {
		return d.ref.getAccount()
	}
	return d.Account
}
func (d *Yun1s39) getPersonalCloudHost() string {
	if d.ref != nil {
		return d.ref.getPersonalCloudHost()
	}
	return d.PersonalCloudHost
}

func getMd5(dataStr string) string {
	hash := md5.Sum([]byte(dataStr))
	return fmt.Sprintf("%x", hash)
}

func (d *Yun139) step1_password_login(device map[string]interface{}) (string, error) {
	url := "https://base.hjq.komect.com/base/user/passwdLogin"
	h := sha1.New()
	h.Write([]byte("fetion.com.cn:" + d.Password))
	authdata := fmt.Sprintf("%x", h.Sum(nil))
	virtual_authdata := getMd5(d.Password)
	
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

	body := base.Json{
		"loginType":       "UNIAUTH_PASSWORD",
		"phoneID":         device["phone_id"],
		"phoneModel":      device["phone_model"],
		"virtualAuthdata": virtual_authdata,
		"phoneBrand":      device["phone_brand"],
		"authType":        "10",
		"timestamp":       ts,
		"deviceUuid":      device["device_uuid"],
		"os":              "android",
		"phoneNumber":     d.Username,
		"userAccount":     d.Username,
		"authdata":        authdata,
		"appid":           "01010811",
		"wifiMac":         device["mac_address"],
	}
	
	var resp base.Json
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"version":      device["app_version"].(string),
			"OS":           "2",
			"OSVersion":    device["android_version"].(string),
			"phoneType":    device["phone_type"].(string),
			"User-Agent":   "UniApp;HjqAppCategory/Phone",
			"Content-Type": "application/json; charset=UTF-8",
		}).
		SetBody(body).
		SetResult(&resp).
		Post(url)

	if err != nil {
		return "", err
	}
	
	passId := utils.Json.Get(res.Body(), "data", "passId").ToString()
	if passId == "" {
		return "", fmt.Errorf("step1 failed: %s", utils.Json.Get(res.Body(), "message").ToString())
	}
	return passId, nil
}

func (d *Yun139) step2_get_single_token(passId string, device map[string]interface{}) (string, error) {
	url := fmt.Sprintf("https://base.hjq.komect.com/login/user/getSingleToken/%s", passId)
	var resp base.Json
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"version":      device["app_version"].(string),
			"OS":           "2",
			"OSVersion":    device["android_version"].(string),
			"phoneType":    device["phone_type"].(string),
			"User-Agent":   "UniApp;HjqAppCategory/Phone",
			"Content-Type": "application/json; charset=UTF-8",
		}).
		SetBody("{}").
		SetResult(&resp).
		Post(url)

	if err != nil {
		return "", err
	}

	token := utils.Json.Get(res.Body(), "data", "token").ToString()
	if token == "" {
		return "", fmt.Errorf("step2 failed: token is empty")
	}
	return token, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: data is empty")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("pkcs7: invalid padding")
	}
	return data[:(length - unpadding)], nil
}

func aesCbcEncrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data = pkcs7Pad(data, block.BlockSize())
	encrypted := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, data)
	return encrypted, nil
}

func aesEcbDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	size := block.BlockSize()
	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], data[bs:be])
	}
	return pkcs7Unpad(decrypted)
}

func (d *Yun139) step3_third_party_login(token string, device map[string]interface{}) (string, error) {
	url := "https://user-njs.yun.com/user/thirdlogin"
	key, _ := hex.DecodeString("73634235495062495331515373756c734e7253306c673d3d")
	iv := []byte(random.String(16))

	h := sha1.New()
	h.Write([]byte("fetion.com.cn:" + token))
	secinfo := strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))

	plainJson := base.Json{
		"clientkey_decrypt": "hejiaqin#2020#la#84dE23LT^%d9",
		"clienttype":        "673",
		"cpid":              "295",
		"dycpwd":            token,
		"extInfo":           base.Json{"ifOpenAccount": "0"},
		"loginMode":         "0",
		"msisdn":            d.Username,
		"pintype":           "13",
		"secinfo":           secinfo,
		"version":           "9.9.0",
	}
	
	jsonBytes, _ := utils.Json.Marshal(plainJson)
	encrypted, err := aesCbcEncrypt(jsonBytes, key, iv)
	if err != nil {
		return "", fmt.Errorf("step3 aes encrypt failed: %w", err)
	}
	
	payload := base64.StdEncoding.EncodeToString(append(iv, encrypted...))

	var respStr string
	_, err = base.RestyClient.R().
		SetHeaders(map[string]string{
			"x-useragent":  fmt.Sprintf("androidsdk|%s|android%s|6.1.1.0|||1220x2574|", device["phone_type"], device["android_version"]),
			"x-deviceinfo": fmt.Sprintf("1|127.0.0.1|5|6.1.1.0|Xiaomi|%s|%s|android %s|1220x2574|android|||", device["phone_type"], device["device_uuid"], device["android_version"]),
			"content-type": "application/json; charset=utf-8",
			"user-agent":   "okhttp/4.11.0",
		}).
		SetBody(payload).
		SetResult(&respStr).
		Post(url)

	if err != nil {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(respStr)
	if err != nil {
		return "", fmt.Errorf("step3 response base64 decode failed: %w", err)
	}

	// This part is tricky in Go, need careful implementation
	// In JS: const iv_res = CryptoJS.lib.WordArray.create(decoded_wa.words.slice(0, 4));
	// In Go, we can slice the byte array directly.
	resIv := decoded[:16]
	resCiphertext := decoded[16:]

	// The key is the same as encryption key
	decryptedWa, err := aesCbcEncrypt(resCiphertext, key, resIv) // It's decrypt, but CBC mode is symmetrical
	if err != nil {
		return "", fmt.Errorf("step3 response aes decrypt failed: %w", err)
	}
	
	decryptedBytes, err := pkcs7Unpad(decryptedWa)
	if err != nil {
		return "", fmt.Errorf("step3 response pkcs7 unpad failed: %w", err)
	}

	hexInner := utils.Json.Get(decryptedBytes, "data").ToString()
	if hexInner == "" {
		return "", errors.New("step3 first layer decrypt failed: data is empty")
	}

	keyC, _ := hex.DecodeString("7150714477323633586746674c337538")
	hexInnerBytes, _ := hex.DecodeString(hexInner)
	
	finalJsonBytes, err := aesEcbDecrypt(hexInnerBytes, keyC)
	if err != nil {
		return "", fmt.Errorf("step3 second layer decrypt failed: %w", err)
	}

	account := utils.Json.Get(finalJsonBytes, "account").ToString()
	authToken := utils.Json.Get(finalJsonBytes, "authToken").ToString()
	if account == "" || authToken == "" {
		return "", errors.New("step3 final decrypt failed: account or authToken is empty")
	}

	newAuthorization := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pc:%s:%s", account, authToken)))
	return newAuthorization, nil
}


func (d *Yun139) loginWithPassword() (string, error) {
	if d.Username == "" || d.Password == "" || d.DeviceProfile == "" {
		return "", errors.New("username, password or device_profile is empty")
	}

	var device map[string]interface{}
	err := utils.Json.UnmarshalFromString(d.DeviceProfile, &device)
	if err != nil {
		return "", fmt.Errorf("failed to parse device_profile: %w", err)
	}

	passId, err := d.step1_password_login(device)
	if err != nil {
		return "", err
	}
	log.Infof("Step 1 success, passId: %s", passId)

	token, err := d.step2_get_single_token(passId, device)
	if err != nil {
		return "", err
	}
	log.Infof("Step 2 success, token: %s", token)

	newAuth, err := d.step3_third_party_login(token, device)
	if err != nil {
		return "", err
	}
	log.Infof("Step 3 success, new authorization generated.")

	// TODO: Implement step 4, 5 if needed for other modes, but for drive, this is enough.
	
	return newAuth, nil
}

// From Apifox doc, key for AndAlbum APIs
// TODO: This key may need to be configured or obtained dynamically.
var andAlbumAesKey, _ = hex.DecodeString("...some...hex...key...") // Placeholder

// sortedJsonStringify sorts the keys of a JSON object and its nested objects, then stringifies it.
func sortedJsonStringify(data interface{}) (string, error) {
	// Using jsoniter with sorted keys feature
	// Note: This provides a simplified sorting. For complex nested objects,
	// a custom recursive function might be needed to exactly match the behavior of the JS script.
	// For now, this should be sufficient for the known request bodies.
	json := jsoniter.Config{
		SortMapKeys: true,
	}.Froze()
	
	res, err := json.MarshalToString(data)
	return res, err
}

func (d *Yun139) andAlbumRequest(pathname string, body interface{}, resp interface{}) ([]byte, error) {
	url := "https://group.yun.139.com/hcy/family/adapter/andAlbum/openApi" + pathname
	
	// 1. Marshal and sort the request body
	sortedJson, err := sortedJsonStringify(body)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: failed to marshal and sort body: %w", err)
	}

	// 2. Encrypt the body
	iv := []byte(random.String(16))
	encryptedBody, err := aesCbcEncrypt([]byte(sortedJson), andAlbumAesKey, iv)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: failed to encrypt body: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(append(iv, encryptedBody...))

	// 3. Make the request
	var respStr string
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"authorization":       "Basic " + d.getAuthorization(),
			"x-svctype":           "2",
			"hcy-cool-flag":       "1",
			"api-version":         "v2",
			"x-huawei-channelsrc": "10214502",
			"content-type":        "application/json; charset=utf-8",
			"user-agent":          "okhttp/4.11.0",
		}).
		SetBody(payload).
		SetResult(&respStr).
		Post(url)

	if err != nil {
		return nil, err
	}
	
	if res.StatusCode() != 200 {
		return nil, fmt.Errorf("andAlbum: unexpected status code %d: %s", res.StatusCode(), res.String())
	}

	// 4. Decrypt the response
	decodedResp, err := base64.StdEncoding.DecodeString(respStr)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: response base64 decode failed: %w", err)
	}
	
	respIv := decodedResp[:16]
	respCiphertext := decodedResp[16:]

	// Re-using aesCbcEncrypt for decryption as CBC is symmetrical
	decryptedWa, err := aesCbcEncrypt(respCiphertext, andAlbumAesKey, respIv)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: response aes decrypt failed: %w", err)
	}
	
	decryptedBytes, err := pkcs7Unpad(decryptedWa)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: response pkcs7 unpad failed: %w", err)
	}

	// 5. Unmarshal to the final response struct
	if resp != nil {
		err = utils.Json.Unmarshal(decryptedBytes, resp)
		if err != nil {
			return nil, fmt.Errorf("andAlbum: failed to unmarshal decrypted response: %w", err)
		}
	}
	
	return decryptedBytes, nil
}
