import sys
import os
import enum
import socket
import re
import select

cache = {}

class HttpRequestInfo(object):
    """
    Represents a HTTP request information
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        """
        
        httpstr = self.method.upper() + " " + self.requested_path + " HTTP/1.0\r\n"
        httpstr += "Host: " + self.requested_host
        if self.requested_port != 80:
            httpstr+= ":" + str(self.requested_port)
        
        httpstr+= "\r\n"

        for h in self.headers:
            if h[0].lower() == "host":
                continue
            httpstr += h[0] + ": " + h[1] + "\r\n"

        httpstr += "\r\n"

        return httpstr

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        return str(self.code) + " " + self.message + "\r\n\r\n"

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    setup_server_socket(proxy_port_number)


def service_http_request(conn, clientaddr, request_str):
    http_request_info = http_request_pipeline(clientaddr, request_str)

    if isinstance(http_request_info, HttpErrorResponse):
        http_str = http_request_info.to_http_string()
        http_bytes = http_request_info.to_byte_array(http_str)
 
        respond_to_client(conn, clientaddr, http_bytes)
    else:    
        # check if request exists in cache
        if http_request_info.requested_host+http_request_info.requested_path in cache:
            http_response = cache[http_request_info.requested_host+http_request_info.requested_path]
        else:
            http_response = setup_client_socket(http_request_info)

        cache[http_request_info.requested_host+http_request_info.requested_path] = http_response
        respond_to_client(conn, clientaddr, http_response)


def respond_to_client(conn, clientaddr, http_response):
    conn.send(bytes(http_response))


def setup_client_socket(http_request_info):
    http_string = http_request_info.to_http_string()
    http_bytes = http_request_info.to_byte_array(http_string)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (http_request_info.requested_host, http_request_info.requested_port)
    
    client_socket.connect(server_address)

    client_socket.send(http_bytes)

    response = []

    while True:
        data = client_socket.recv(1)
        if data == "".encode("ascii"):
            break
        response += data

    return response


def setup_server_socket(proxy_port_number):
    print("Starting HTTP proxy on port:", proxy_port_number)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", proxy_port_number))
    server_socket.setblocking(0)
    server_socket.listen(20)

    inputs = [server_socket]
    outputs = []
    request_queues = {}
    

    while inputs:
        # check to see which sockets are readable, writable, exceptional
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        
        for s in readable:
            # server socket is ready to be read from
            # accept new client (new connection)
            if s is server_socket:
                connection, client_address = s.accept()
                connection.setblocking(0)
                #append connection to inputs (sockets we might want to read from)
                inputs.append(connection)
                request_queues[connection] = []
            else:
                #we are receiving data from a client
                data = []
                data += s.recv(5)
                #if they sent actual data (not an empty string), add it to corresponding socket's msg queue
                if data:
                    q = request_queues[s]
                    if len(q) > 0:
                        bytearr = q[len(q) - 1]
                        ending = bytearr + data
                        # if request is complete, remove from inputs and add to outputs
                        if ending[-4:] == [13, 10, 13, 10]:
                            inputs.remove(s)
                            if s not in outputs:
                                outputs.append(s)
                    
                    request_queues[s].append(data)


        for s in writable:
            #socket s's request is ready to be serviced
            request_str = get_request_str(request_queues[s])
            service_http_request(s, s.getpeername(), request_str)
            s.close()
            outputs.remove(s)
            

def get_request_str(queue):
    # converts bytes from queue into a request string

    request_str = ""
    while len(queue) > 0:
        bytearr = queue[0]
        queue = queue[1:]
        request_str += bytes(bytearr).decode("ascii")
    
    return request_str


def http_request_pipeline(source_addr, http_raw_data):
    validity = check_http_request_validity(http_raw_data)

    if validity is not HttpRequestState.GOOD:
        if validity is HttpRequestState.INVALID_INPUT:
            http_error_response = HttpErrorResponse(400, "Bad Request")
        elif validity is HttpRequestState.NOT_SUPPORTED:
            http_error_response = HttpErrorResponse(501, "Not Implemented")
       
        return http_error_response

    http_request_info = parse_http_request(source_addr, http_raw_data) 
    sanitize_http_request(http_request_info)
    
    return http_request_info


def parse_http_request(source_addr, http_raw_data):
    method = None
    host = None
    path = None
    version = None
    port = 80
    headerslist = []

    requestln = http_raw_data[:http_raw_data.index('\n')] 

    match = re.search(r"([a-zA-Z-._~:/?%#[\]@!$&'()*+,;=0-9]+)\s+([a-zA-Z-._~:/?%#[\]@!$&'()*+,;=0-9]+)\s+([a-zA-Z-._~:/?%#[\]@!$&'()*+,;=0-9]+)", requestln)
    
    if match != None:
        method = match.group(1).strip()
        path = match.group(2).strip()
        port, port_idx = get_port_num(path)

        if port_idx != -1:
            port_digits = len(str(port))+1
            path = path[:port_idx] + path[port_idx+port_digits:]
        version = match.group(3).strip().lower()
        
    headers = http_raw_data[http_raw_data.index('\n')+1:]
    
    tupleslist = re.findall(r"([a-zA-Z0-9 -]+):[^\n\ra-zA-Z/:.0-9();,+=*\" -]*([a-zA-Z/:.0-9();,+=*\" -]+)", headers)

    for h in tupleslist:
        h = list(h)
        headerslist.append(h)
        h[0] = h[0].strip()
        h[1] = h[1].strip()
        if h[0].lower() == "host":
            host = h[1]
            if port == 80:
                port, port_idx = get_port_num(h[1])
            if port_idx!=-1:
                h[1] = h[1][0:port_idx]

    ret = HttpRequestInfo(source_addr, method, host, port, path, headerslist)
    return ret


def get_port_num(str):
    if str == None:
        return 80, -1

    match = re.search(":\d+", str)
    if match != None:
        port = int(match.group()[1:])
        return port, str.find(match.group())

    return 80, -1


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    http_request_info = parse_http_request(None, http_raw_data)

    method = http_request_info.method
    port = http_request_info.requested_port
    host = http_request_info.requested_host
    path = http_request_info.requested_path

    if method is None or path is None:
        return HttpRequestState.INVALID_INPUT

    # check if there are any invalid headers
    http_raw_data = http_raw_data[:-4]
    num_of_headers = len(http_raw_data.split("\r\n")) - 1

    if num_of_headers != len(http_request_info.headers):
        return HttpRequestState.INVALID_INPUT

    # check to see if there is a relative path without a host
    if path[0] == "/" and host is None:
        return HttpRequestState.INVALID_INPUT
        
    method = method.lower()
    if method == "get":
        print("method is GET")
    elif method == "head" or method == "post" or method == "put":
        return HttpRequestState.NOT_SUPPORTED
    else:
        return HttpRequestState.INVALID_INPUT
    
    if port < 0 or port > 65536:
        return HttpRequestState.INVALID_INPUT

    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo):
    method = request_info.method
    port = request_info.requested_port
    host = request_info.requested_host
    path = request_info.requested_path

    http_request = ""
    if host is not None:
        if host.find("http://") != -1:
            request_info.requested_host = request_info.requested_host[7:]
        elif host.find("https://") != -1:
            request_info.requested_host = request_info.requested_host[8:]
        return request_info


    if path.find("http://") != -1:
        path = path[7:]
    elif path.find("https://") != -1:
        path = path[8:]

    if path.find("/") != -1:
        host = path[: path.index("/")]
        path = path[path.index("/") :]

    request_info.requested_path = path
    request_info.requested_host = host    


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()