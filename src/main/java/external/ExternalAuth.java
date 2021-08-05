package external;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;


@WebServlet(name = "ExternalAuth", urlPatterns = {"/Authn/External/*"})
public class ExternalAuth extends HttpServlet {
    private final Logger logger = LoggerFactory.getLogger(ExternalAuth.class);

    private static final String AUTHN_EXCEPTION = "CustomException";

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {

        try {
            // 1. Call ExternalAuthentication.startExternalAuthentication(HttpServletRequest), saving off the result as a key.
            final String key = ExternalAuthentication.startExternalAuthentication(request);

            // 2. Do work as necessary (reading request details from the attributes below). Any redirects must preserve the key
            // value returned in step 1 because it must be used to complete the login later.
            try {

                // Initiate a HashSet of principals. We will transform this into a subject later.
                HashSet<Principal> principals = new HashSet<Principal>();

                // Prompt user to a form where we can extract their username
                // Reach out to an external directory to get more information about the user
                // This is also where logic will be done on whether the user should be directed to Beyond Identity or not
                principals.add(new UsernamePrincipal("harry.guo@cornell.com"));

                // 3. Set request attributes to communicate the result of the login back.
                IdPAttribute attr = new IdPAttribute("useBeyondIdentity");
                attr.setValues(Collections.singleton(new StringAttributeValue("true")));
                principals.add(new IdPAttributePrincipal(attr));

                // Create subject to send back as a result of the External module
                request.setAttribute(ExternalAuthentication.SUBJECT_KEY, new Subject(false, principals, Collections.EMPTY_SET, Collections.EMPTY_SET));


                // 4. Call ExternalAuthentication.finishExternalAuthentication(String, HttpServletRequest, HttpServletResponse).
                // The first parameter is the key returned in step 1.
                ExternalAuthentication.finishExternalAuthentication(key, request, response);


            } catch (Exception e) {
                request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AUTHN_EXCEPTION);
                ExternalAuthentication.finishExternalAuthentication(key, request, response);
                return;
            }
        } catch (final ExternalAuthenticationException e) {
            throw new ServletException("Error processing external authentication request", e);

        }
    }

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);
    }

}
