from coapthon.resources.resource import Resource


class BasicResource(Resource):

    def __init__(self, name="BasicResource", coap_server=None):
        super(BasicResource, self).__init__(name, coap_server, visible=True,
                                            observable=True, allow_children=True)
        self.payload = "Basic Resource"

    def render_GET(self, request):
        return self

    def render_PUT(self, request):
        self.payload = request.payload
        return self

    def render_POST(self, request):
        res = BasicResource()
        res.location_query = request.uri_query
        res.payload = request.payload
        return res

    def render_DELETE(self, request):
        return True

    def render_GET_advanced(self, request, response):
        pass

    def render_PUT_advanced(self, request, response):
        pass

    def render_POST_advanced(self, request, response):
        pass

    def render_DELETE_advanced(self, request, response):
        pass
