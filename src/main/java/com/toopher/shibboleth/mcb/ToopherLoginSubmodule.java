/* The MIT License (MIT)

Copyright (c) 2014 Toopher, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


package com.toopher.shibboleth.mcb;

import com.toopher.ToopherIframe;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBAttributeResolver;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBLoginServlet;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBSubmodule;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBUsernamePrincipal;
import edu.internet2.middleware.assurance.mcb.authn.provider.ui.IDPUIHandler;
import edu.internet2.middleware.assurance.mcb.exception.UserInitiatedLoginFailureException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.velocity.VelocityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This sub-module handles Toopher authentication for the Multi-Context Broker
 * 
 * @author David Langenberg <dave@dlmcomputing.com>
 */
public class ToopherLoginSubmodule implements MCBSubmodule{

	private final Logger log = LoggerFactory.getLogger(ToopherLoginSubmodule.class);
	
	private String beanName = null;
	
	private String consumerKey;
	private String consumerSecret;
	private String loginPage;
	private String emailAttribute;
	private boolean toopherManual;
	private boolean toopherChallenge;
	
	private ToopherIframe t;
	
	private static final SecureRandom secureRandom = new SecureRandom();
	
	/**
	 * Constructor
	 * 
	 * @param key Consumer Key from toopher requester
	 * @param secret Consumer Secret from toopher requester
	 * @param challenge Should the users be forced to do the Toopher Challenge (true/false)
	 * @param manual Should the users be forced to have toopher's automation disabled (true/false)
	 * @param emailAttribute the attribute from the attribute-resolver that contains (single-valued) the authoritative email address for the user -- used in resets
	 * @param loginPage velocity template containing toopher page
	 * @param apiUrl used for on-prem deployments -- tells us to use the on-prem server & where to find it.
	 */
	public ToopherLoginSubmodule(String key, String secret, String challenge, String manual, String emailAttribute, String loginPage, String apiUrl){
		initialize(key, secret, challenge, manual, emailAttribute, loginPage, apiUrl);
	}
	
	/**
	 * Constructor
	 * 
	 * @param key Consumer Key from toopher requester
	 * @param secret Consumer Secret from toopher requester
	 * @param challenge Should the users be forced to do the Toopher Challenge (true/false)
	 * @param manual Should the users be forced to have toopher's automation disabled (true/false)
	 * @param emailAttribute the attribute from the attribute-resolver that contains (single-valued) the authoritative email address for the user -- used in resets
	 * @param loginPage velocity template containing toopher page
	 */
	public ToopherLoginSubmodule(String key, String secret, String challenge, String manual, String emailAttribute, String loginPage){
		initialize(key, secret, challenge, manual, emailAttribute, loginPage, null);
	}
	
	protected void initialize(String key, String secret, String challenge, String manual, String emailAttribute, String loginPage, String apiUrl){
		consumerKey = key;
		consumerSecret = secret;
		toopherChallenge = "true".equalsIgnoreCase(challenge);
		toopherManual = "false".equalsIgnoreCase(manual);
		this.emailAttribute = emailAttribute;
		
		this.loginPage = loginPage;
		
		if(apiUrl == null || apiUrl.equalsIgnoreCase("")){
			t = new ToopherIframe(consumerKey, consumerSecret);
		}else{
			log.info("Using Toopher On-Prem located at {}", apiUrl);
			t = new ToopherIframe(consumerKey, consumerSecret, apiUrl);
		}
		
		log.debug("Config {}: consumer key:{}, consumer secret:{}, login page: {}, toopherChallenge: {}, toopherManual: {}, user mail attribute: {}", beanName,key, secret, loginPage, challenge, manual, emailAttribute);
	}
	
	/**
	 * Display the Toopher login screen
	 * 
	 * @param servlet
	 * @param request
	 * @param response
	 * @return
	 * @throws AuthenticationException
	 * @throws LoginException 
	 */
	public boolean displayLogin(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, LoginException {
		//this module must be invoked after a principal has already been established
		MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);
		log.debug("principal name is: {}", principal.getName());
		if(principal == null || principal.getName() == null || principal.getName().equals("") || principal.getName().equals("[principal]")){
			log.error("The ToopherLoginSubmodule may not be invoked unless the user already has authenticated using another method.  No user principal detected.");
			return false;
		}
		
		//create secure token for this AuthN & save it in the session
		String requestToken = new BigInteger(20*8,secureRandom).toString(32);
		log.debug("request token is {}", requestToken);
		
		request.getSession().setAttribute("ToopherRequestToken", requestToken);
		
		String userEmail = getUserEmail(request, response, servlet, principal);
		IDPUIHandler idpui = new IDPUIHandler(request,servlet.getServletContext());
		
		String serviceName = idpui.getServiceName();
		if(serviceName == null || serviceName.equals("")){
			log.debug("No service name in Metadata, falling back to EntityID for service name");
			serviceName = idpui.getEntityID();
		}
		
		String authIframeURL = t.authUri(principal.getName(), (userEmail == null ? "" : userEmail),serviceName, toopherManual, toopherChallenge, requestToken, "performAuthentication", 60);
		log.debug("URL for iFrame is {}",authIframeURL);
		
		
		VelocityContext vCtx = new VelocityContext();
		vCtx.put("iframeRequestURL",authIframeURL);
		
		log.debug("Displaying Velocity Toopher template [{}]",loginPage);
		servlet.doVelocity(request, response, loginPage, vCtx);
		
		return true;
	}

	/**
	 * Process the response from the Login Screen
	 * @param servlet
	 * @param request
	 * @param response
	 * @return
	 * @throws AuthenticationException
	 * @throws LoginException 
	 */
	public boolean processLogin(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, LoginException {
		String requestToken = (String)request.getSession().getAttribute("ToopherRequestToken");
		log.debug("request token is {}",requestToken);
		
		MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);
		
		try{
			Map<String,String> validatedData = t.validate(request.getParameterMap(), requestToken);
			
			if(validatedData.containsKey("error_code")){
				//Check for API errors
				String errorCode = validatedData.get("error_code");
				log.debug("received error code for principal {}: {}",principal.getName(),errorCode);
				
				if(errorCode.equals(ToopherIframe.PAIRING_DEACTIVATED)){
					//user deleted the pairing of their device -- display paring UI
					log.info("principal {} was pared, but is presently not.  Sending off to pair.", principal.getName());
					doPairing(servlet,request, response, requestToken, principal);
					return false;
				} else if(errorCode.equals(ToopherIframe.USER_OPT_OUT)){
					//user marked as opt-out in toopher API, grant access
					log.info("principal {} is in opt-out mode in toopher.  Access allowed.", principal.getName());
					return true;
				} else if(errorCode.equals(ToopherIframe.USER_UNKNOWN)){
					//user has never done Toopher on this server before
					log.info("principal {} has not been paired before.  Sending off to pair.", principal.getName());
					doPairing(servlet,request, response, requestToken, principal);
					return false;
				}
			}
			
			boolean authPending = validatedData.get("pending").toLowerCase().equals("true");
			boolean authGranted = validatedData.get("granted").toLowerCase().equals("true");
			
			log.debug("authPending is {} && authGranted is {}", authPending, authGranted);
			
			boolean result = authGranted && !authPending;
			
			if(result){
				return result;
			} else if (authGranted == false){
				//either authGranted is false or authPending is true
				log.warn("Principal {} pressed the deny button on their device.");
				throw new UserInitiatedLoginFailureException();
			} else {
				throw new AuthenticationException("Unknown Toopher error");
			}
					
			
		}catch(ToopherIframe.SignatureValidationError e){
			//signature was invalid
			log.warn("Signature was invalid on data returned from Toopher: {}", e.getMessage());
			principal.setFailedLogin("unable to verify signature");
			return false;
		}
	}

	public void init() {
		log.info("Toopher Login Submodule version {} initialized", getClass().getPackage().getImplementationVersion());
	}

	public String getBeanName() {
		return beanName;
	}

	public void setBeanName(String string) {
		beanName = string;
	}

	/**
	 * If we get here, we need to display a pairing UI.  Same UI as above, but different URL
	 * 
	 */
	private void doPairing(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response,String requestToken, MCBUsernamePrincipal principal) throws AuthenticationException {
		VelocityContext vCtx = new VelocityContext();
		vCtx.put("iframeRequestURL",t.pairUri(principal.getName(), getUserEmail(request, response, servlet, principal)));
		
		log.debug("Displaying Velocity Toopher template [{}]",loginPage);
		
		servlet.doVelocity(request, response, loginPage, vCtx);
		
	}
	
	/**
	 * Gets the email address of the user from the email attribute
	 * @param request 
	 * @param response
	 * @param servlet
	 * @param principal
	 * @return empty string if no email address else the user's email address
	 * @throws AuthenticationException 
	 */
	private String getUserEmail(HttpServletRequest request, HttpServletResponse response, MCBLoginServlet servlet, MCBUsernamePrincipal principal) throws AuthenticationException {
		IDPUIHandler idpui = new IDPUIHandler(request,servlet.getServletContext());
		log.debug("resolving attributes for principal {}",principal.getName());
		MCBAttributeResolver ar = new MCBAttributeResolver();
		ar.resolve(servlet, request, response, principal.getName(), idpui.getEntityID());
		
		Map<String,BaseAttribute> attrs = ar.getAttributes();
		log.debug("have attributes");
		
		String userEmail = "";
		
		if(attrs.containsKey(emailAttribute)){
			userEmail = (String) attrs.get(emailAttribute).getValues().toArray()[0];
		}
		
		log.debug("userEmail is {}",userEmail);
		return userEmail;
	}
	
}
