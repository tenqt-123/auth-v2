; ==============================================================================
; QUỐC THÁI AUTH CLIENT FOR AUTOHOTKEY (AHK)
; Dành cho các công cụ auto, bot game, macro Windows viết bằng AutoHotkey
; Tương thích 100% với hệ thống QuocThaiAuth
; Sử dụng đối tượng COM chuẩn: WinHttp.WinHttpRequest.5.1
; ==============================================================================

global QTA_AppId   := "app_pk_viet_9a8b7c6d5e4f"
global QTA_BaseUrl := "https://quocthaiauth.onrender.com"
global QTA_Token   := ""
global QTA_HWID    := ""

; Sinh HWID duy nhất cho máy tính chạy AHK
QuocThaiAuth_GetHWID() {
    if (QTA_HWID != "")
        return QTA_HWID
    hwid := A_ComputerName . "-" . A_UserName . "-" . A_OSVersion
    QTA_HWID := "HWID-AHK-" . SubStr(RegExReplace(hwid, "[^a-zA-Z0-9]", ""), 1, 16)
    return QTA_HWID
}

; Hàm gửi HTTP POST JSON tới máy chủ
QuocThaiAuth_Post(endpoint, jsonBody) {
    hwid := QuocThaiAuth_GetHWID()
    url := RTrim(QTA_BaseUrl, "/") . "/api/v1/client" . endpoint
    try {
        http := ComObjCreate("WinHttp.WinHttpRequest.5.1")
        http.Open("POST", url, false)
        http.SetRequestHeader("Content-Type", "application/json; charset=UTF-8")
        http.SetRequestHeader("x-app-id", QTA_AppId)
        http.SetRequestHeader("x-hwid", hwid)
        http.SetRequestHeader("User-Agent", "QuocThaiAuth-AHK/1.0")
        if (QTA_Token != "")
            http.SetRequestHeader("Authorization", "Bearer " . QTA_Token)
        http.SetTimeouts(5000, 5000, 10000, 10000)
        http.Send(jsonBody)
        return http.ResponseText
    } catch e {
        return "{""success"":false,""error"":""Khong the ket noi toi server""}"
    }
}

; 1. Khởi tạo kết nối
QuocThaiAuth_Init() {
    hwid := QuocThaiAuth_GetHWID()
    json := "{""appId"":""" . QTA_AppId . """,""hwid"":""" . hwid . """}"
    res := QuocThaiAuth_Post("/init", json)
    if InStr(res, """success"":true")
        return true
    return false
}

; 2. Xác thực bằng Mã Key Bản Quyền
QuocThaiAuth_LoginKey(licenseKey) {
    hwid := QuocThaiAuth_GetHWID()
    key := Trim(licenseKey)
    json := "{""key"":""" . key . """,""hwid"":""" . hwid . """,""appId"":""" . QTA_AppId . """}"
    res := QuocThaiAuth_Post("/login", json)
    if InStr(res, """success"":true")
        return true
    return false
}

; 3. Xác thực bằng Tài Khoản & Mật Khẩu
QuocThaiAuth_LoginUser(username, password) {
    hwid := QuocThaiAuth_GetHWID()
    u := Trim(username)
    p := Trim(password)
    json := "{""username"":""" . u . """,""password"":""" . p . """,""hwid"":""" . hwid . """,""appId"":""" . QTA_AppId . """}"
    res := QuocThaiAuth_Post("/login-user", json)
    if InStr(res, """success"":true")
        return true
    return false
}

; ==============================================================================
; VÍ DỤ SỬ DỤNG TRONG TOOL AHK:
; ==============================================================================
/*
; Khởi tạo kết nối:
if (!QuocThaiAuth_Init()) {
    MsgBox, 16, Lỗi, Không thể kết nối tới máy chủ bản quyền!
    ExitApp
}

; Nhập key kiểm tra:
InputBox, myKey, QuocThaiAuth, Nhập mã key bản quyền của bạn:, , 340, 140
if (ErrorLevel || myKey = "")
    ExitApp

if (QuocThaiAuth_LoginKey(myKey)) {
    MsgBox, 64, Thành công, Xác thực bản quyền thành công! Tool bắt đầu chạy...
    ; Đặt code tool/bot của bạn tại đây
} else {
    MsgBox, 16, Thất bại, Mã key không hợp lệ hoặc đã hết hạn!
    ExitApp
}
*/
