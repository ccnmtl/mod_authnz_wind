#version 0.9.3
from mod_python import apache,util,Session
import urllib,re

WIND_SERVICE = 'cnmtl_full_np'
LOGOUT_URL='https://wind.columbia.edu/logout'
LOGIN_URL='https://wind.columbia.edu/login'
VALIDATE_URL='https://wind.columbia.edu/validate'
TICKET_ARG = 'ticketid'
ALT_AUTH_ARG = 'nowindauth'
LOGOUT_ARG = 'windlogout'

def authenhandler(req):
    if req.main is not None:
        #defer to the main request's auth
        if getattr(req.main,'user',False):
            req.user = req.main.user
                
            if hasattr(req.main,'groups'):
                req.groups = req.main.groups
            elif req.connection.notes.has_key('groups'):
                req.groups = req.connection.notes['groups']
            return apache.OK
        else:
            return apache.HTTP_UNAUTHORIZED

    q=req.parsed_uri[apache.URI_QUERY]
    args={}
    if q is not None:
        args=util.parse_qs(q)

    #at least in modpy 3.1 if there is a '//' after the domain, 
    #   it might not parse args correctly, and won't find LOGOUT_ARG
    if args.has_key(LOGOUT_ARG):
        req.user=""
        if req.connection.notes.has_key('user'):
            del req.connection.notes['user']
        req.status=apache.HTTP_UNAUTHORIZED
        try:
           session = Session.Session(req)
           session.delete()
        except:
           pass
        util.redirect(req,LOGOUT_URL)

    if args.has_key(ALT_AUTH_ARG):
        #this 'feature' may be handy if we want to try basic auth too
        #but it might not work (UNTESTED)
        return apache.DECLINED

    if req.connection.notes.has_key('user'):
        #HACK:session only works per-request, and hangs when called by the same connection
        req.user = req.connection.notes['user']
        req.groups = req.connection.notes['groups']
        return apache.OK

    session = Session.Session(req)
        
    if session.has_key('user'):
        req.user=session['user']
        req.groups=session['groups']
        req.connection.notes['user']=req.user
        req.connection.notes['groups']=getattr(req,'groups','')
        return apache.OK

    if args.has_key(TICKET_ARG):
        ticket=args[TICKET_ARG][-1]
        validation=validate_wind_ticket(ticket)
        if validation[0]:
            req.user = validation[1]
            if not req.user:
                return apache.HTTP_EXPECTATION_FAILED
            req.groups = ','.join(validation[2])
            session['user'] = req.user
            session['groups'] = req.groups
            req.connection.notes['user']= req.user
            req.connection.notes['groups']= req.groups

            session.save()
            return apache.OK
        else:
            redirectWind(req)
    else:
        redirectWind(req)
    #should never get here
    apache.log_error('unexpected condition')
    return apache.HTTP_UNAUTHORIZED

def authzhandler(req):
    """
    Check whether the user's WIND groups match any required groups
    """
    #Checking for valid-user and 'user' lines might
    #be extraneous.  Apache seems to check these before authz is called
    if not req.user:
        return apache.HTTP_UNAUTHORIZED

    #split but avoid ''.split(',') == [''] empty string group
    my_groups = [g for g in getattr(req,'groups','').split(',') if g]

    requires=req.requires()
    if len(requires)==0:
        return apache.OK
    for require in requires:
        if require=='valid-user':
            return apache.OK
        s=require.split(' ')
        if s[0]=='user':
            for u in s[1:]:
                if u==req.user:
                    return apache.OK
        if s[0]=='group':
            for g in s[1:]:
                if g in my_groups:
                    return apache.OK
    return apache.HTTP_FORBIDDEN

def redirectWind(req):
    """redirects session to Wind server"""
    req.user=""
    req.status=apache.HTTP_UNAUTHORIZED
    destination = re.sub('(?<=[&?])'+TICKET_ARG+'=.*?(\&|\Z)',
                         '',
                         req.unparsed_uri)
    destination = re.sub('\&(?=(\&|\Z))','',destination)

    port = ''
    protocol = 'http'
    if req.parsed_uri[5]:
        port = ':'+str(req.parsed_uri[5])
    try: #is_https() only in mod_python 3.2; try req.parsed_uri[0] for mod_python 3.1, but it doesn't always work
        if req.is_https():
            protocol = 'https'
    except:
        apache.log_error( 'support for https requires mod_python 3.2', apache.APLOG_WARNING)
        
    util.redirect(req,LOGIN_URL+'?service=%s&destination=%s://%s%s%s' % ( WIND_SERVICE,protocol,req.hostname,port,urllib.quote(destination) ))

    
def validate_wind_ticket(ticketid):
    """
    checks a wind ticketid.
    if successful, it returns (1,username,groups)
    otherwise it returns (0,error message)
    """
    
    if ticketid == "":
        return (0,'no ticketid')
    uri = VALIDATE_URL+"?"+TICKET_ARG+"=%s" % ticketid
    response = urllib.urlopen(uri).read()
    lines = response.split("\n")
    if lines[0] == "yes":
        username = lines[1]
        groups = [line for line in lines[2:] if line != ""]
        return (1,username,groups)
    elif lines[0] == "no":
        return (0,"The ticket was already used or was invalid.",[])
    else:
        return (0,"WIND did not return a valid response.",[])
        

def handler(req):
    """
    This is just for debugging purposes.
    This shouldn't be used as a content-handler
    """
    req.content_type = 'text/html'
    req.write("Hello World, %s\n" % req.user)
    req.write("Groups: %s\n" % req.groups)
    req.write("<br />Required auth:"+repr(req.requires()))
    req.write('<br /><a href="%s?%s=true">logout</a>' % (req.uri, LOGOUT_ARG))
    return apache.OK
