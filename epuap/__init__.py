import base64
import requests
from uuid import uuid4

from urllib.parse import urlencode
from lxml.builder import ElementMaker
from lxml import etree as et

from django.http import HttpResponseRedirect
from django.utils import timezone


base_url = 'https://hetman.epuap.gov.pl'
security_server = base_url + '/DracoEngine2/draco.jsf'
tp_signing_url = 'https://pz.gov.pl/pz-services/tpSigning'
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
NS_ENC = "http://schemas.xmlsoap.org/soap/encoding/"
SAML_ARTIFACT_SVC_URL = security_server + '/axis2/services/EngineSAMLArtifact'

tenant_app_name = 'https://rekrutacja.ozarow-mazowiecki.pl'  # trzeba to brac z modelu tenanta
# app_name w powyższym przykładzie to nazwa mojej domyślnej skrytki w ePUAP

SEM = ElementMaker(namespace=NS_SAMLP, nsmap={
    'saml': NS_SAML,
    'samlp': NS_SAMLP,
})

def get_time_stemp():
    return timezone.now().isoformat()


def gen_id():
    return "_" + str(uuid4())


def bytes_encoder(text):
    if not type(text) == bytes:
        text = bytearray(text, 'UTF-8')
    return base64.encodebytes(text)


def create_authn_request_url(request):
    el = SEM(
        'AuthnRequest',
        SEM('Issuer', tenant_app_name),
        ID=gen_id(),
        Version="2.0",
        IssueInstant=get_time_stemp(),
        Destination=security_server,
        IsPassive="false",
        AssertionConsumerServiceURL=request.build_absolute_uri(),
    )
    xml = et.tostring(el, encoding='UTF-8')
    return security_server + '?' + urlencode({
        'SAMLRequest': bytes_encoder(xml)
    })


def create_artifact_resolve_xml(artifact):
    return SEM(
        'ArtifactResolve',
        SEM('Issuer', tenant_app_name),
        SEM('Artifact', artifact),
        ID=gen_id(),
        IssueInstant=get_time_stemp(),
        Version="2.0",
    )


def create_soap_env_xml(body):
    e = ElementMaker(namespace=NS_ENV, nsmap={'soap': NS_ENV})
    return e("Envelope", e("Body", body),
             {"{%s}encodingStyle" % NS_ENV: NS_ENC})


def soap_call(url, method, xml, requests_session=None):
    msg = et.tostring(
        create_soap_env_xml(xml),
        xml_declaration=True,
        encoding='UTF-8',
    )
    response = (requests_session or requests).post(url, msg, headers={
        "Content-Type": "text/xml; charset=UTF-8",
        'SOAPAction': '"%s"' % method,
        'Accept-Encoding': 'UTF-8',
    })

    return et.fromstring(response.content).xpath(
        "/ns:Envelope/ns:Body",
        namespaces={"ns": NS_ENV},
    )[0]

def start(request):
    request = HttpResponseRedirect(create_authn_request_url(
        request
    ))
    import pdb;pdb.set_trace()
    if request.status_code == 200:
        if request.GET.get('SAMLart'):
            # tu prawdopoodbnie przekazujemy dokument do podpisania

            import pdb;pdb.set_trace()
            doc = None
            success_url = None
            failure_url = None
            body = add_doc(doc, success_url, failure_url)
            xml = encode_xml(generate(body))
            sign_document(xml)



            response = soap_call(
                SAML_ARTIFACT_SVC_URL,
                'artifactResolve',
                create_artifact_resolve_xml(request.GET['SAMLart']),
            )
            import pdb;pdb.set_trace()
            ns = {'saml': NS_SAML}
            assertion = response.xpath("//saml:Assertion", namespaces=ns)
            assertion = assertion and assertion[0]
            import pdb; pdb.set_trace()
            if assertion:
                data = {
                    "TGSID": assertion.xpath("@ID", namespaces=ns)[0],
                    "username": assertion.xpath(
                        "saml:Subject/saml:NameID/text()",
                        namespaces=ns,
                    )[0],
                    "expires": assertion.xpath(
                        "saml:Conditions/@NotOnOrAfter",
                        namespaces=ns,
                    )[0],
                }


def add_doc(doc, success_url, failure_url, additional_info=None):
    begin = '<sig:addDocumentToSigning>'
    end = '</sig: addDocumentToSigning>'
    context = """<doc>{document}</doc>
    <successURL>{success}</successURL>
    <failureURL>{fail}</failureURL>
    <additionalInfo>{info}</additionalInfo>""".format(
        document=doc,
        success=success_url,
        fail=failure_url,
        info=additional_info,
    )

    return begin + '\n' + context + '\n ' + end


# def get_signed_document(doc_url):
#     begin = '<sig:getSignedDocument>'
#     end = '</sig:getSignedDocument>'
#     context = '<id>{}</id>'.format(doc_url)
#
#     return begin + '\n' + context + '\n ' + end


# def verify(doc_hash):
#     begin = '<sig:verifySignedDocument>'
#     end = '</sig:verifySignedDocument>'
#     context = '<document>{}</document>'.format(doc_hash)
#
#     return begin + '\n' + context + '\n ' + end


def generate(body):
    file_url = 'doc.xml'
    input_after_line = '<soapenv:Body>'
    with open(file_url) as file:
        file_data = file.read()
        xml = file_data.replace(input_after_line, input_after_line + body)
    file.close()
    return xml


def encode_xml(xml):
    return bytes_encoder(xml)


def sign_document(xml):
    # headers = {'content-type': 'application/soap+xml'}
    headers = {'content-type': 'text/xml'}

    response = requests.post(tp_signing_url, data=xml, headers=headers)
    response_text = response.text
    try:
        document_url = response_text['addDocumentToSigningReturn']
    except:
        pass
    import pdb;pdb.set_trace()


def is_signed(success_url, document_url):
    return True if success_url == document_url else False
