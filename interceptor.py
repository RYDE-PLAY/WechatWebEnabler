from mitmproxy import http
from urllib import parse


QQ_BROWSER_EXTSPAM = "Go8FCIkFEokFCggwMDAwMDAwMRAGGvAESySibk50w5Wb3uTl2c2h64jVVrV7gNs06GFlWplHQbY/5FfiO++1yH4ykCyNPWKXmco+wfQzK5R98D3so7rJ5LmGFvBLjGceleySrc3SOf2Pc1gVehzJgODeS0lDL3/I/0S2SSE98YgKleq6Uqx6ndTy9yaL9qFxJL7eiA/R3SEfTaW1SBoSITIu+EEkXff+Pv8NHOk7N57rcGk1w0ZzRrQDkXTOXFN2iHYIzAAZPIOY45Lsh+A4slpgnDiaOvRtlQYCt97nmPLuTipOJ8Qc5pM7ZsOsAPPrCQL7nK0I7aPrFDF0q4ziUUKettzW8MrAaiVfmbD1/VkmLNVqqZVvBCtRblXb5FHmtS8FxnqCzYP4WFvz3T0TcrOqwLX1M/DQvcHaGGw0B0y4bZMs7lVScGBFxMj3vbFi2SRKbKhaitxHfYHAOAa0X7/MSS0RNAjdwoyGHeOepXOKY+h3iHeqCvgOH6LOifdHf/1aaZNwSkGotYnYScW8Yx63LnSwba7+hESrtPa/huRmB9KWvMCKbDThL/nne14hnL277EDCSocPu3rOSYjuB9gKSOdVmWsj9Dxb/iZIe+S6AiG29Esm+/eUacSba0k8wn5HhHg9d4tIcixrxveflc8vi2/wNQGVFNsGO6tB5WF0xf/plngOvQ1/ivGV/C1Qpdhzznh0ExAVJ6dwzNg7qIEBaw+BzTJTUuRcPk92Sn6QDn2Pu3mpONaEumacjW4w6ipPnPw+g2TfywJjeEcpSZaP4Q3YV5HG8D6UjWA4GSkBKculWpdCMadx0usMomsSS/74QgpYqcPkmamB4nVv1JxczYITIqItIKjD35IGKAUwAA=="
QQ_BROWSER_CLIENT_VERSION = "2.0.0"

WX_URLS = [
    "https://wx.qq.com/",
    "https://web.wechat.com/",
    "https://wx2.qq.com/",
    "https://wx8.qq.com/"
]
WX_HOSTS = [
    "wx.qq.com",
    "web.wechat.com",
    "wx2.qq.com",
    "wx8.qq.com"
]

class Interceptor:

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host in WX_HOSTS:
            url = flow.request.url
            scheme, netloc, path, query, fragment = parse.urlsplit(url)
            if path == '/' and query.find("target=t") == -1:
                query_params = parse.parse_qs(query)
                query_params["target"] = "t"
                new_query = parse.urlencode(query=query_params, doseq=True)
                redirect_url = parse.urlunsplit((scheme, netloc, path, new_query, fragment))
                flow.response = http.Response.make(
                    status_code=302,
                    content=b'',
                    headers={
                        "Location": redirect_url,
                    }
                )
            elif path == '/cgi-bin/mmwebwx-bin/webwxnewloginpage':
                flow.request.headers['extspam'] = QQ_BROWSER_EXTSPAM
                flow.request.headers['client-version'] = QQ_BROWSER_CLIENT_VERSION

addons = [Interceptor()]
