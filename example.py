# THIS IS EXAMPLE CODE AND IS PROVIDED AS-IS.
# This script will sign in to Tableau Server, ask for a list of users, and then sign out.
# The script works in Python 2.x and 3.x and has no dependencies outside the standard library.

# Before you can make REST API requests to Tableau Server, you must enable the REST API.
# For more information, see http://onlinehelp.tableausoftware.com/current/server/en-us/help.htm#rest_api_requ.htm

try:
    # Python 3.x
    from urllib.request import urlopen, request
except:
    # Python 2.x
    from urllib2 import urlopen, Request

# For parsing XML responses
import xml.etree.ElementTree as ET

class RESTAPI:
    '''Defines a class that represents a RESTful connection to Tableau Server.'''
    def __init__(self, server, username, password, site=""):
        self.server = server
        self.site = ""
        self.username = username
        self.password = password
        self.token = None # Holds the login token from the Sign In call
        self.site_id = ""

    def _is_xml(self, req):
        '''Utility function to check whether the response includes XML.'''
        try:
            return req.info()['content-type'].find('application/xml') == 0
        except:
            return False

    def _make_login_payload(self, username, password, site):
        '''Generates the XML payload for the Sign In call.
           Pass the username and password of an administrator
           user.
        '''
        _payload = """<tsRequest><credentials name="%s" password="%s" ><site contentUrl="%s" /></credentials></tsRequest>"""
        return _payload % (username, password, site)

    def _build_api_url(self, call):
        '''Utility function to build the URL string. Example:
            https://server/api/2.0/sites/abcd-123-6789/datasources
        '''
        return self.server + "/api/2.0" + call

    def _call_api(self, url, data=None):
        '''Makes the call to the specified API, passing the session auth token
           via the X-tableau-auth header. This function reads the result.
           If the result includes XML, the function returns an ElementTree object,
           otherwise it returns the HTTP status code.
        '''
        req = Request(url, headers = {'X-tableau-auth': self.token}, data=data)
        req = urlopen(req)
        resp = req.read().decode("utf8")
        if self._is_xml(req):
            return ET.fromstring(resp)
        else:
            return req.getcode()

    def signin(self):
        '''Builds the Sign In call payload, signs in,
        gets the site ID id for the default site, and displays the auth token.
        '''
        # Make the login XML payload
        payload = self._make_login_payload(self.username, self.password, self.site)

        # Makes the HTTP call, sending the payload that contains the username and password.
        resp = urlopen(self.server + "/api/2.0/auth/signin", data=payload.encode("utf8"))

        # Reads the response.
        return_xml = resp.read().decode("utf8")

        # Parses the response into XML.
        cred_xml = ET.fromstring(return_xml)

        # Extracts the auth token from the response. The token is passed
        # via a header for subsequent calls.
        print return_xml
        for child in cred_xml:
           print child.tag, child.attrib
        print cred_xml[0].get('token')

        self.token = cred_xml[0].get('token')
        print self.token
        print("Sign-in successful! Token: {0}".format(self.token))

        # Gets the site ID for the Default site. This ID can be used in subsequent calls.
        self.site_id = self.query_site_id('Default')

    def signout(self):
        '''Ends the current session by deleting the token.'''
        api_call = self._build_api_url("/auth/signout")
        self._call_api(api_call, data=b'')
        print("Sign-out successful for token: {0}".format(self.token))

    def query_datasources(self):
        '''Returns an XML payload with the list of datasources on the current site.'''
        api_call = self._build_api_url("/sites/{0}/datasources".format(self.site_id))
        return self._call_api(api_call)

    def query_site_id(self, site_name):
        '''Gets the ID for the specified site.'''
        api_call = self._build_api_url("/sites/{0}?key=name".format(site_name))
        # Parse the XML and grab the site-id
        site_id = self._call_api(api_call).find('{http://tableausoftware.com/api}site').attrib['id']
        return site_id

    def get_projects(self):
        api_call = self._build_api_url("/sites/?includeProjects=true")
        project_xml = self._call_api(api_call)

        sites = project_xml.find("{http://tableausoftware.com/api}sites")

        site = sites.find("{http://tableausoftware.com/api}site")
        projects = site.find("{http://tableausoftware.com/api}projects")

        for p in projects:
            print p.tag, p.attrib
       
#        for child in sites:
#            for project in child:
#                for proj in project:
#                    print proj.tag, proj.attrib

    def get_views(self):
        api_call = self._build_api_url("/sites/{0}/users/{1}/workbooks".format(self.site_id,"e4cd3c8e-8cda-4113-9515-2950abd03b77"))
        workbooks_xml = self._call_api(api_call)

        workbooks = workbooks_xml.find("{http://tableausoftware.com/api}workbooks")
        print(ET.tostring(workbooks_xml))

        print workbooks

        for wbk in workbooks:
            print wbk.tag

 

    def get_users(self):
        '''Requests a list of users and returns a dictionary object of name : user-id'''
        api_call = self._build_api_url("/sites/{0}/users".format(self.site_id))
        user_xml = self._call_api(api_call)
        # Parse the XML and grab the username and id for each user
        user_dict = dict([(user.attrib['name'], user.attrib['id']) for user in user_xml.find("{http://tableausoftware.com/api}users")])
        return user_dict

if __name__ == '__main__':
    #Sets up a REST API instance.

	# NOTE: To use HTTPS, enable SSL on Tableau Server. For more information, see
    # http://onlinehelp.tableausoftware.com/current/server/en-us/help.htm#ssl_config.htm
    # Substitute your own values for <server_name>, <username>, and <password>. Use credentials
    # for a user who is defined as an administrator.
    tab_srv = RESTAPI('http://10.100.162.5', 'tableauadmin', 'icq-Fn2wTg')

    # Calls Sign In.
    tab_srv.signin()

    # Calls Get Users and saves the result.
    users = tab_srv.get_users()


    # Prints the dictionary of users and IDs.
    print(users)
    
    tab_srv.get_views()
    # tab_srv.get_projects()

    # Prints the raw response from the query._datasources call. The information is in an ElementTree object.
    datasources = tab_srv.query_datasources()
    print(datasources)

    # Calls Sign Out and ends the session.
    tab_srv.signout()

