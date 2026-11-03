import pytest

from allfiltro.normaliza import ValorInvalido, dominio, ip, linha_de_fonte, valor


def test_dominio():
    assert dominio("https://WWW.ESPN.com:443/futebol?x=1") == "espn.com"
    assert dominio("ação.com.br") == "xn--ao-siap.com.br"
    assert dominio("ge.globo.com.") == "ge.globo.com"
    for ruim in ("*.x.com", "semponto", "a..b.com", "-a.com", "1.2.3.4"):
        with pytest.raises(ValorInvalido):
            dominio(ruim)


def test_ip():
    assert ip("10.1.2.3/8") == "10.0.0.0/8"
    assert ip("200.1.2.3/32") == "200.1.2.3"
    assert valor("2001:db8::1/64") == ("ip", "2001:db8::/64")


def test_linhas_de_fonte():
    assert linha_de_fonte("0.0.0.0 ads.x.com", "hosts") == ("dominio", "ads.x.com")
    assert linha_de_fonte("||tracker.y.com^$third-party", "adblock") == ("dominio", "tracker.y.com")
    assert linha_de_fonte("*.blaze.com", "dominios") == ("dominio", "blaze.com")
    assert linha_de_fonte("# comentario", "dominios") is None
    assert linha_de_fonte("1.2.3.0/24 ; drop", "ips") == ("ip", "1.2.3.0/24")
