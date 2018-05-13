/*
 * Copyright 2018 Administrator.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package me.chanjar.weixin.common.util.crypto;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import com.icbc.crypto.utils.Base64;
import com.icbc.crypto.utils.RSA;
import java.io.File;
/**
 *
 * @author Administrator
 */
public class IcbcCryptUtil {
	/**
	 * 加密
	 * @param data 数据
	 * @param path 路径
	 * @return byte[] 返回值
	 * @throws Exception 
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String path) throws Exception {
		String base64Text = Base64.icbcbase64encode(data);
		return RSA.icbcRsaPriEn(base64Text.getBytes(), path);
	}
	
	/**
	 * 解密
	 * @param data 解密数据
	 * @param path 解密路径
	 * @return byte[] 返回数据
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String path) throws Exception {
		byte[] plainText = RSA.icbcRsaPubDe(data, path);
		return Base64.icbcbase64decode(new String(plainText));
	}
        
        public static String encrypt(String signature, String timestamp, String pub_key_path, String priv_key_path) {
            String endata="";
            try{
			byte[] base64Data = Base64.icbcbase64decode(URLDecoder.decode(signature,"utf-8"));
			byte[] deData = decryptByPublicKey(base64Data, pub_key_path);
			signature = new String(deData);
			if(signature.equals(timestamp)){
				byte[] enData = encryptByPrivateKey(deData, priv_key_path);
                                
				endata=Base64.icbcbase64encode(enData);				
			}            
            }catch(Exception e){
                throw new RuntimeException("融e联签名校验失败");
            }
            
            return endata;
        }
        
}
