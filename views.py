from flask import Flask, render_template, session, request, Response
from pylti.flask import lti
import settings
import logging
import json
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
app.secret_key = settings.secret_key
app.config.from_object(settings.configClass)


# ============================================
# Logging
# ============================================

formatter = logging.Formatter(settings.LOG_FORMAT)
handler = RotatingFileHandler(
    settings.LOG_FILE,
    maxBytes=settings.LOG_MAX_BYTES,
    backupCount=settings.LOG_BACKUP_COUNT
)
handler.setLevel(logging.getLevelName(settings.LOG_LEVEL))
handler.setFormatter(formatter)
app.logger.addHandler(handler)


# ============================================
# Utility Functions
# ============================================

def return_error(msg):
    return render_template('error.htm.j2', msg=msg)


def error(exception=None):
    app.logger.error("PyLTI error: {}".format(exception))
    return return_error('''Authentication error,
        please refresh and try again. If this error persists,
        please contact support.''')


# ============================================
# Web Views / Routes
# ============================================

# LTI Launch
@app.route('/launch', methods=['POST', 'GET'])
@lti(error=error, request='initial', role='any', app=app)
def launch(lti=lti):
    """
    Returns the launch page
    request.form will contain all the lti params
    """

    # example of getting lti data from the request
    # let's just store it in our session
    session['lis_person_name_full'] = request.form.get('lis_person_name_full')

    # Write the lti params to the console
    app.logger.info(json.dumps(request.form, indent=2))

    return render_template('launch.htm.j2', lis_person_name_full=session['lis_person_name_full'])


# Home page
@app.route('/', methods=['GET'])
def index(lti=lti):
    return render_template('index.htm.j2')


#JWT test
@app.route('/jwt_launch_via_json', methods=['POST', 'GET'])
def jwt_launch_via_json():
    from jose import jwk, jws, jwt
    from jose.utils import base64url_decode
    import requests

    #from keys import public_key, private_key
    print("=-=-=-=-=-=- REQUEST FORM -=-=-=-=-=")
    print(json.dumps(request.form, indent=2))
    
    #jwt
    id_token = request.form.get('id_token')
    audience='407321823'

    #key id
    kid = jws.get_unverified_header(id_token)['kid']

    #get platform web keys from lti-ri
    r = requests.get(settings.JSON_KEY_URL)
    
    #todo - get key based on KID
    web_keys = r.json()['keys'][0]

    #create key from web keys
    key = jwk.construct(web_keys)


    try:
        #Verify JWT
        lti_data = jwt.decode(id_token, web_keys, algorithms=['RS256'], audience=audience)

        print("=-=-=-=-=-=- LTI DATA -=-=-=-=-=")
        print(lti_data)

        return "Hello %s! <br> JWT Successfully Decoded and verified." % lti_data['name']

    except:  
        return "There was an error verifying the JWT."


    return "Should not get here"





# #JWT test
@app.route('/jwt_launch', methods=['POST', 'GET'])
def jwt_launch():
    #return render_template('index.htm.j2')
    import jwt
    import json
    from jose import jws

    from keys import public_key, private_key
    
    print(json.dumps(request.form, indent=2))
    id_token = str.encode(request.form.get('id_token'))
    audience= settings.AUDIENCE

    #python-jose
    # try:
    #     verified = jws.verify(id_token, public_key, algorithms=['RS256'])
    #     return "JWT Successfully Decoded and verified."
    # except:
    #     return "There was an error verifying the JWT."
    
    #pyjwt
    try:
        decoded = jwt.decode(id_token, public_key, audience=audience, algorithms='RS256')
        print(decoded)
        return "Hello %s! <br> JWT Successfully Decoded and verified." % decoded['name']
    except:
        return "There was an error verifying the JWT."
    
    return json.dumps(decoded)
    #return "hi"







# LTI XML Configuration
@app.route("/xml/", methods=['GET'])
def xml():
    """
    Returns the lti.xml file for the app.
    XML can be built at https://www.eduappcenter.com/
    """
    try:
        return Response(render_template(
            'lti.xml.j2'), mimetype='application/xml'
        )
    except:
        app.logger.error("Error with XML.")
        return return_error('''Error with XML. Please refresh and try again. If this error persists,
            please contact support.''')
