package me.chanjar.weixin.common.bean;

import org.testng.Assert;
import org.testng.annotations.Test;

@Test
public class WxAccessTokenTest {

  public void testFromJson() {

    //String json = "{\"access_token\":\"ACCESS_TOKEN\",\"expires_in\":7200}";
	String json="{\"signature\":\"signature\",\"token\":\"{\"expiredtime\":\"21600\",\"accesstoken\":\"token\",\"sessionkey\":\"sessionkey\"}\"}";
	
    WxAccessToken wxError = WxAccessToken.fromJson(json);
    Assert.assertEquals(wxError.getSessionKey(), "sessionkey");
    Assert.assertEquals(wxError.getAccessToken(), "token");
    Assert.assertTrue(wxError.getExpiresIn() == 7200);

  }

}
