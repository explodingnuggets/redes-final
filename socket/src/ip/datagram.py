class Datagram():
    def __init__(self, fragment_sz):
        self.fragments = {}
        self.fragment_sz = fragment_sz
        self.received_last = False
        self.callback = None

    
    def push_fragment(self, frag_off, data):
        self.fragments[frag_off] = data
