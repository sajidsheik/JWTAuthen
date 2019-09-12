
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;


public class AuthorizationFilter extends OncePerRequestFilter {
	
	static final String KEYFACTORY = "RSA";
	static final String JWT_TYPE = "JWT";
	static final String JWT_ALGORITHM = "RS256";

	@Value("${apigee.jwt.claim.iss}")
	private String iss;
	
	@Value("${apigee.jwt.claim.sub}")
	private String sub;

	@Value("${apigee.jwt.pubkey}")
	private String publickey;

	@Value("${apigee.jwt.enabled}") 
	private boolean authorizationRequired;
	

	private static final Logger log = LoggerFactory.getLogger(AuthorizationFilter.class);
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		
		if (!authorizationRequired) {
			log.info("Set apigee.jwt.enabled in the application.properties to true to enable the JWT verification");
		}
		
		try {
    		if(request != null && !(request.getServletPath().equals("/ping") || request.getServletPath().equals("/deepping") || request.getServletPath().equals("/config")) && authorizationRequired && !request.getServerName().equalsIgnoreCase("localhost") ) {
    			
    			log.info("Inside JWT verification process method");
    			
	    		String header = request.getHeader("Authorization");
	    	
	    		if (header == null || !header.startsWith("Bearer ")) {
	    			throw new Exception("No JWT token found in request headers");
	    		}

	    		// strip out just the JWT
	    		String jwtToken = header.substring(7);

	    		byte[] publicBytes = Base64.getDecoder().decode(publickey.getBytes());
	    		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
	    		KeyFactory keyFactory = KeyFactory.getInstance(KEYFACTORY);
	    		PublicKey pubKey = keyFactory.generatePublic(keySpec);

	    		// check JwsHeader for presence of type and algorithm
	    		@SuppressWarnings("rawtypes")
	    		final JwsHeader jwsHeader = Jwts.parser().setSigningKey(pubKey).parseClaimsJws(jwtToken).getHeader();
	    		String jwtType = jwsHeader.getType();
	    		String jwtAlgorithm = jwsHeader.getAlgorithm();
	    		if (!((jwtType.equals(JWT_TYPE)) && (jwtAlgorithm.equals(JWT_ALGORITHM)))) {
	    			throw new Exception("Invalid JWT Type or Algorithm");
	    		}

	    		final Claims claims = Jwts.parser().setSigningKey(pubKey).parseClaimsJws(jwtToken).getBody();

	    		String issuer = claims.getIssuer();
	    		String subject = claims.getSubject();
	    		if (!((issuer.equals(iss)) && (subject.contains(sub)))) {
	    			throw new Exception("Invalid JWT Issuer or Subject");
	    		}
    		}
    		filterChain.doFilter(request, response);
	    		
		} catch (Exception e) {
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			//response.setContentType(request.getContentType() == null || request.getContentType().isEmpty() ? MediaType.APPLICATION_JSON_VALUE : request.getContentType());

				response.getOutputStream().println(e.getMessage());
			
		}
	}
}
