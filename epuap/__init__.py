import base64
import requests
from uuid import uuid4

from urllib.parse import urlencode
from lxml.builder import ElementMaker
from lxml import etree as et

from django.http import HttpResponseRedirect
from django.views.generic import CreateView
from django.utils import timezone


# BASE_URL = 'https://hetman.epuap.gov.pl'
# AUTHN_URL = BASE_URL + '/DracoEngine2/draco.jsf'
# SAML_ARTIFACT_SVC_URL = BASE_URL + "/axis2/services/EngineSAMLArtifact"
#
# NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
# NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
# NS_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
# NS_ENC = "http://schemas.xmlsoap.org/soap/encoding/"
#
# SEM = ElementMaker(namespace=NS_SAMLP, nsmap={
#     'saml': NS_SAML,
#     'samlp': NS_SAMLP,
# })
#
#
# def create_authn_request_url(authn_url, redirect_url):
#
#     el = SEM('AuthnRequest', SEM('{%s}Issuer' % NS_SAML),
#         ID=gen_id(), Version="2.0", IssueInstant=gen_ts(), Destination=authn_url,
#         IsPassive="false", AssertionConsumerServiceURL=redirect_url)
#
#     xml = ET.tostring(el, encoding='UTF-8')
#     import pdb;pdb.set_trace()
#     return authn_url + '?' + urlencode({
#         'SAMLRequest': base64.encodebytes(deflate(xml))
#     })
#
#
# def create_logout_request_url(authn_url, username):
#     el = SEM('LogoutRequest', SEM('{%s}Issuer' % NS_SAML, app_name), SEM('NameID', username),
#         ID=gen_id(), Version="2.0", IssueInstant=gen_ts())
#
#     xml = ET.tostring(el, encoding='UTF-8')
#
#     return authn_url + '?' + urlencode({
#         'SAMLRequest': base64.encodebytes(deflate(xml))
#     })
#
#
# def create_artifact_resolve_xml(artifact):
#     return SEM('ArtifactResolve',
#         SEM('{%s}Issuer' % NS_SAML),
#         SEM('Artifact', artifact),
#         ID=gen_id(), IssueInstant=gen_ts(), Version="2.0")
#
#
# def create_soap_env_xml(body):
#     E = ElementMaker(namespace=NS_ENV, nsmap={'soap':NS_ENV})
#     return E("Envelope", E("Body", body), {"{%s}encodingStyle" % NS_ENV: NS_ENC})
#
#
# def soap_call(url, method, doc, requests_session = None):
#     msg = ET.tostring(create_soap_env_xml(doc), xml_declaration=True, encoding='UTF-8')
#     resp = (requests_session or requests).post(url, msg, headers={
#         "Content-Type": "text/xml; charset=UTF-8",
#         'SOAPAction': '"%s"' % method,
#         'Accept-Encoding': 'UTF-8',
#     })
#
#     return ET.fromstring(resp.content).xpath("/ns:Envelope/ns:Body", namespaces={"ns": NS_ENV})[0]
#
# # utils
#
#
# def deflate(data):
#     return encode(data, "zlib")
#
#
# def gen_ts():
#     return datetime.datetime.utcnow().isoformat() + "Z"
#
#
# def gen_id():
#     return "_" + str(uuid.uuid4())
#
# # view decorator for Django
#
#
# def epuap_login_required():
#     def epuap_login_required_decorator(view):
#         def wrapper(request, *args, **kwargs):
#             if not "EPUAP" in request.session or request.session["EPUAP"].get("expires") < gen_ts() or 'epuap_force_auth' in request.GET:
#                 if 'SAMLart' in request.GET:
#                     resp = soap_call(SAML_ARTIFACT_SVC_URL, 'artifactResolve', create_artifact_resolve_xml(app_name, request.GET['SAMLart']))
#                     ns = {'saml': NS_SAML}
#                     assertion = resp.xpath("//saml:Assertion", namespaces=ns)
#                     assertion = assertion and assertion[0]
#                     if assertion:
#                         data = {
#                             "TGSID": assertion.xpath("@ID", namespaces=ns)[0],
#                             "username": assertion.xpath("saml:Subject/saml:NameID/text()", namespaces=ns)[0],
#                             "expires": assertion.xpath("saml:Conditions/@NotOnOrAfter", namespaces=ns)[0],
#                         }
#                         request.session["EPUAP"] = data
#                     return view(request, *args, **kwargs)
#
#                 import pdb;pdb.set_trace()
#                 return HttpResponseRedirect(create_authn_request_url(
#                     AUTHN_URL, app_name, request.build_absolute_url()))
#             return view(request, *args, **kwargs)
#         return wrapper
#     return epuap_login_required_decorator
#
#
# # custom PZ configuration and functions


class Sign(CreateView):
    template_name = None

    base_url = 'https://hetman.epuap.gov.pl'
    security_server = base_url + '/DracoEngine2/draco.jsf'
    artefact_url = base_url + "/axis2/services/EngineSAMLArtifact"
    tp_signing = 'https://pz.gov.pl/pz-services/tpSigning'
    NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
    NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
    NS_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
    NS_ENC = "http://schemas.xmlsoap.org/soap/encoding/"

    tanant_app_name = 'bla/bla' # trzeba to brac z modelu tenanta
    # app_name w powyższym przykładzie to nazwa mojej domyślnej skrytki w ePUAP

    SEM = ElementMaker(namespace=NS_SAMLP, nsmap={
        'saml': NS_SAML,
        'samlp': NS_SAMLP,
    })

    @staticmethod
    def get_time_stemp():
        time = timezone.now().isoformat()
        date = time[:10]
        time = time[10:]
        return date + 'T' + time

    @staticmethod
    def gen_id():
        return "_" + str(uuid4())

    @staticmethod
    def bytes_encoder(text):
        return base64.encodebytes(bytearray(text, 'UTF-8'))

    def create_authn_request_url(self, request):
        el = self.SEM(
            'AuthnRequest',
            self.SEM('{}Issuer'.format(self.NS_SAML)),
            ID=self.gen_id(),
            Version="2.0",
            IssueInstant=self.get_time_stemp(),
            Destination=self.security_server,
            IsPassive="false",
            AssertionConsumerServiceURL=request.build_absolute_url(),
        )

        xml = et.tostring(el, encoding='UTF-8')
        return self.security_server + '?' + urlencode({
            'SAMLRequest': self.bytes_encoder(xml)
        })

    def create_logout_request_url(self, username):
        el = self.SEM(
            'LogoutRequest', self.SEM('{}Issuer'.format(self.NS_SAML)),
            self.SEM('NameID', username),
            ID=self.gen_id(),
            Version="2.0",
            IssueInstant=self.get_time_stemp(),
        )

        xml = et.tostring(el, encoding='UTF-8')

        return self.authn_url + '?' + urlencode({
            'SAMLRequest': self.bytes_encoder(xml)
        })

    def create_artifact_resolve_xml(self, artifact):
        return self.SEM(
            'ArtifactResolve',
            self.SEM('{%s}Issuer' % self.NS_SAML, self.tanant_app_name),
            self.SEM('Artifact', artifact),
            ID=self.gen_id(),
            IssueInstant=self.get_time_stemp(),
            Version="2.0",
        )

    def create_soap_env_xml(self, body):
        e = ElementMaker(namespace=self.NS_ENV, nsmap={'soap': self.NS_ENV})
        return e("Envelope", e("Body", body),
                 {"{%s}encodingStyle" % self.NS_ENV: self.NS_ENC})

    def soap_call(self, url, method, xml, requests_session=None):
        msg = et.tostring(
            self.create_soap_env_xml(xml),
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
            namespaces={"ns": self.NS_ENV},
        )[0]

    def get(self, request, *args, **kwargs):
        request = HttpResponseRedirect(self.create_authn_request_url(
            request
        ))
        if 'SAMLart' in request.GET:
            response = self.soap_call(
                self.SAML_ARTIFACT_SVC_URL,
                'artifactResolve',
                self.create_artifact_resolve_xml(request.get('SAMLart')),
            )

            ns = {'saml': self.NS_SAML}
            assertion = response.xpath("//saml:Assertion", namespaces=ns)
            assertion = assertion and assertion[0]
            import pdb;pdb.set_trace()
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
                # TODO tu odpalamy opcje podpsiania dokumentu

                # request.session["EPUAP"] = data

        # return super().get(request, *args, **kwargs)


class WSDLFileGenerator:
    @staticmethod
    def add_doc(doc, success_url, failure_url, additional_info=None):
        begin = '<sig:addDocumentToSigning>'
        end = '</sig: addDocumentToSigning>'
        context = """<doc>{document}</doc>
        <successURL>{success}</successURL>
        <failureURL>{fail}</failureURL>
        <additionalInfo>{info}</additionalInfo>""".format(
            document=doc,
            success=success_url,
            fai0l=failure_url,
            info=additional_info,
        )

        return begin + '\n' + context + '\n ' + end

    @staticmethod
    def get_signed_document(doc_url):
        begin = '<sig:getSignedDocument>'
        end = '</sig:getSignedDocument>'
        context = '<id>{}</id>'.format(doc_url)

        return begin + '\n' + context + '\n ' + end

    @staticmethod
    def verify(doc_hash):
        begin = '<sig:verifySignedDocument>'
        end = '</sig:verifySignedDocument>'
        context = '<document>{}</document>'.format(doc_hash)

        return begin + '\n' + context + '\n ' + end

    @staticmethod
    def generate(body):
        file_url = 'doc.xml'
        input_after_line = '<soapenv:Body>'
        with open(file_url) as file:
            file_data = file.read()
            xml = file_data.replace(input_after_line, input_after_line+body)
        file.close()
        return xml
