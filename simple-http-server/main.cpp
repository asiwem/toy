#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <strings.h>			/* strcasecmp */

#include <iostream>
#include <thread>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <optional>
#include <atomic>
#include <algorithm>

namespace config {
	static constexpr auto
		rxlim_initsz = 1,	/* dumb defaults lets us find bugs quicker */
		port = 3000;
}

namespace http {
	enum header {
		CONNECTION,
		CONTENT_LENGTH,
		TRANSFER_ENCODING,
		HOST,
		ACCEPT,
		USER_AGENT,
		ACCEPT_ENCODING,
		ACCEPT_LANGUAGE,
		IF_NONE_MATCH,
		CACHE_CONTROL,
		CONTENT_TYPE,
		REFERER,
		ORIGIN
	};

	enum status {
		_200_OK,
		_400_BAD_REQUEST,
		_404_NOT_FOUND,
		_500_INTERNAL_SERVER_ERROR
	};

	static constexpr const char *status_str[] = {
		"200 OK",
		"400 Bad Request",
		"404 Not Found",
		"500 Internal Server Error"
	};

	enum protocol {
		HTTP1_0,
		HTTP1_1
	};

	enum method {
		GET,
		HEAD,
		POST
	};

	struct header_key {
		std::string_view view;
	};

	struct header_sep {
	};

	struct header_val {
		std::string_view view;
	};
}

static const std::unordered_map<std::string_view, http::header> known_headers_lowercase = {
	{"connection", http::header::CONNECTION},
	{"content-length", http::header::CONTENT_LENGTH},
	{"transfer-encoding", http::header::TRANSFER_ENCODING},
	{"host", http::header::HOST},
	{"accept", http::header::ACCEPT},
	{"user-agent", http::header::USER_AGENT},
	{"accept-encoding", http::header::ACCEPT_ENCODING},
	{"accept-language", http::header::ACCEPT_LANGUAGE},
	{"if-none-match", http::header::IF_NONE_MATCH},
	{"cache-control", http::header::CACHE_CONTROL},
	{"content-type", http::header::CONTENT_TYPE},
	{"referer", http::header::REFERER},
	{"origin", http::header::ORIGIN}
};

/* indexes must correspond to the enum http::header */
static const std::string_view known_headers[] = {
	"Connection",
	"Content-Length",
	"Transfer-Encoding",
	"Host",
	"Accept",
	"User-Agent",
	"Accept-Encoding",
	"Accept-Language",
	"If-None-Match",
	"Cache-Cotrol",
	"Content-Type",
	"Referer",
	"Origin"
};

template <typename T>
class defer {
public:
	explicit defer(T &&arg) : env{std::forward<T>(arg)}
	{
	}

	~defer()
	{
		env();
	}
public:
	T env;
};

/* no ownership of fd */
class connection {
public:
	explicit connection(int fd)
		: fd{fd}
		, rxbuf{nullptr}
		, rx{0}
		, rxlim{0}
	{
	}

	~connection()
	{
		std::free(rxbuf);
	}

	bool receive()
	{
		if (!rxbuf) {
			rxlim = config::rxlim_initsz;
			rxbuf = (char *) std::malloc(rxlim);
			if (!rxbuf)
				throw std::bad_alloc{};
		}

		if (rx == rxlim) {
			rxlim *= 2;
			rxbuf = (char *) std::realloc(rxbuf, rxlim);
			if (!rxbuf)
				throw std::bad_alloc{};
		}

		auto n = recv(fd, rxbuf+rx, rxlim-rx, 0);
		if (!n) {
			std::printf("info: peer disconnected\n");
			return false;
		}

		if (n < 0) {
			std::fprintf(stderr, "warn: recv errno=%d\n", errno);
			return false;
		}

		rx += n;
		return true;
	}

	void discard(size_t sz)
	{
		if (sz == rx) {
			std::free(rxbuf);
			rxbuf = nullptr;
			rx = 0;
			rxlim = 0;
			return;
		}

		std::memmove(rxbuf, rxbuf+sz, rxlim-sz);
		rx -= sz;

		while (rxlim > (2*rx))
			rxlim /= 2;

		rxbuf = (char *) std::realloc(rxbuf, rxlim);
	}

	void dump_request(size_t sz) const
	{
		timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);

		std::string filename;
		filename.append("logs/")
			.append(std::to_string(ts.tv_sec))
			.append("_")
			.append(std::to_string(ts.tv_nsec));

		auto filefd = std::fopen(filename.c_str(), "wb");
		if (!filefd)
			return;

		defer autoclose{[filefd](){
			if (std::fclose(filefd) < 0)
				std::fprintf(stderr, "warn: fclose errno=%d\n", errno);
		}};

		std::fwrite(rxbuf, 1, sz, filefd);
	}

public:
	int		fd;
	char		*rxbuf;
	size_t		rx, rxlim;
};

class parser {
public:
	struct term {
	};

	struct ascii_word {
		std::string_view view;
	};

	struct rest {
		std::string_view view;
	};
public:
	bool impl(term)
	{
		return *s == '\0';
	}

	bool impl(rest *p)
	{
		p->view = std::string_view{s};
		return true;
	}

	bool impl(size_t *p)
	{
		size_t ret = 0;
		size_t i = 0;

		while (s[i] >= '0' && s[i] <= '9') {
			ret *= 10;
			ret += s[i] - '0';
			i++;
		}

		if (!i)
			return false;

		*p = ret;
		s += i;
		return true;
	}

	bool impl(http::header_sep)
	{
		size_t i = 0;

		if (s[i++] != ':')
			return false;

		while (s[i] == ' ')
			i++;

		s += i;
		return true;
	}

	bool impl(ascii_word *p)
	{
		size_t i = 0;

		while (s[i] >= 0x21 && s[i] <= 0x7E)
			i++;

		if (!i)
			return false;

		p->view = std::string_view{s, i};
		s += i;
		return true;
	}

	bool impl(http::method *p)
	{
		if (impl("GET")) {
			*p = http::method::GET;
			return true;
		}

		if (impl("HEAD")) {
			*p = http::method::HEAD;
			return true;
		}

		if (impl("POST")) {
			*p = http::method::POST;
			return true;
		}

		return false;
	}

	bool impl(http::header_key *p)
	{
		size_t i = 0;

		while ((s[i] >= 'a' && s[i] <= 'z')
			|| (s[i] >= 'A' && s[i] <= 'Z')
			|| (s[i] >= '0' && s[i] <= '9')
			|| (s[i] == '-'))
				i++;

		if (!i)
			return false;

		p->view = std::string_view{s, i};
		s += i;
		return true;
	}

	/* for now only support ASCII chars */
	bool impl(http::header_val *p)
	{
		size_t i = 0;

		while (s[i] >= 0x20 && s[i] <= 0x7E)
			i++;

		if (!i)
			return false;

		p->view = std::string_view{s, i};
		s += i;
		return true;
	}

	bool impl(http::protocol *p)
	{
		if (impl("HTTP/1.0")) {
			*p = http::protocol::HTTP1_0;
			return true;
		}

		if (impl("HTTP/1.1")) {
			*p = http::protocol::HTTP1_1;
			return true;
		}

		return false;
	}

	template <size_t N>
	bool impl(const char (&arr)[N])
	{
		for (size_t i = 0; i != N-1; i++)
			if (s[i] != arr[i])
				return false;
		s += N-1;
		return true;
	}

	template <typename ...Args>
	bool operator()(Args &&...args)
	{
		return (... && impl(std::forward<Args>(args)));
	}
public:
	const char *s;
};

struct request {
	std::string query;
	const std::unordered_map<http::header, std::string> &headers;
	std::string_view peername;
	std::vector<std::string_view> parts;
};

struct response {
	std::string body;
	http::status status;
	std::unordered_map<http::header, std::string> headers;
};

[[maybe_unused]] static bool ends_with(std::string_view v, std::string_view pattern)
{
	return v.substr(v.size()-pattern.size()) == pattern;
}

struct fs_entry {
	std::vector<fs_entry>	files;
	std::string		name;
	off_t			size;
	unsigned char		type;
};

/* fs operations are racy */
static std::optional<std::vector<fs_entry>> read_dirs_sync(std::string path)
{
	auto fd = opendir(path.c_str());
	if (!fd)
		return std::nullopt;

	defer autoclose{[fd](){
		if (closedir(fd) < 0)
			std::fprintf(stderr, "warn: closedir errno=%d\n", errno);
	}};

	/* readdir_r is actually deprecated; readdir was fixed */
	std::vector<fs_entry> vec;
	dirent64 *ptr;
	while ((ptr = readdir64(fd))) {
		if (ptr->d_name[0] == '.')
			continue;

		std::string filename = ptr->d_name;
		std::string fullpath;
		fullpath.append(path)
			.append("/")
			.append(filename);

		struct stat s;
		if (stat(fullpath.c_str(), &s) < 0) {
			std::fprintf(stderr, "warn: stat errno=%d\n", errno);
			return std::nullopt;
		}

		fs_entry e{
			{},
			std::move(filename),
			s.st_size,
			ptr->d_type
		};

		if (ptr->d_type == DT_DIR) {
			auto sub = read_dirs_sync(fullpath);
			if (!sub)
				return std::nullopt;

			e.files = std::move(*sub);
		}

		vec.push_back(std::move(e));
		std::sort(vec.begin(), vec.end(), [](const fs_entry &a, const fs_entry &b){
			return std::strcmp(a.name.c_str(), b.name.c_str()) < 0;
		});
	}

	return vec;
}

/* duplicate headers are allowed */
static bool parse_http_headers(std::unordered_map<http::header, std::string> &map, parser &p)
{
	http::header_key key;
	http::header_val val;
	while (p(&key, http::header_sep{}, &val, "\r\n")) {
		std::string key_lower{key.view};
		for (auto &c : key_lower)
			if (c >= 'A' && c <= 'Z')
				c |= 0x20;

		auto find = known_headers_lowercase.find(key_lower);
		if (find == known_headers_lowercase.end()) {
			std::cout << "unknown: " << key_lower << "\n";
			continue;
		}

		const auto hdr = find->second;
		auto find_request_header = map.find(hdr);
		if (find_request_header == map.end()) {
			map.insert({
				hdr,
				std::string{val.view}
			});
		} else {
			find_request_header->second.append(", ").append(val.view);
		}
	}

	return p("\r\n");
}

static const std::unordered_map<std::string_view, std::string_view> content_type_to_extension = {
	{"text/html", "html"},
	{"text/css", "css"},
	{"text/plain", "txt"},
	{"image/jpg", "jpg"},
	{"image/jpeg", "jpeg"},
	{"image/png", "png"},
	{"image/gif", "gif"},
	{"text/markdown", "md"},
	{"video/quicktime", "mov"},
	{"video/mp4", "mp4"},
	{"application/pdf", "pdf"},
	{"text/x-c++src", "cpp"}
};

static const std::unordered_map<std::string_view, std::string_view> extension_to_content_type = {
	{"html", "text/html"},
	{"css", "text/css"},
	{"txt", "text/plain"},
	{"jpg", "image/jpg"},
	{"jpeg", "image/jpeg"},
	{"png", "image/png"},
	{"gif", "image/gif"},
	{"md", "text/markdown"},
	{"mov", "video/quicktime"},
	{"mp4", "video/mp4"},
	{"pdf", "application/pdf"},
	{"cpp", "text/x-c++src"}
};

static void serve_static_file(std::string s, response &res)
{
	auto fd = std::fopen(s.c_str(), "rb");
	if (!fd) {
		res.status = http::status::_500_INTERNAL_SERVER_ERROR;
		res.headers[http::CONTENT_TYPE] = "text/plain; charset=utf-8";
		res.body.append("Could not serve the file '")
			.append(s)
			.append("'");

		return;
	}

	defer autoclose{[fd](){
		if (std::fclose(fd) < 0)
			std::fprintf(stderr, "warn: fclose errno=%d\n", errno);
	}};

	std::fseek(fd, 0, SEEK_END);
	auto size = std::ftell(fd);
	std::fseek(fd, 0, SEEK_SET);

	res.body.resize(size);
	std::fread(res.body.data(), 1, size, fd);

	const auto rpos = s.find_last_of('.');
	if (rpos != std::string::npos) {
		const auto ext = s.substr(rpos+1);
		const auto find = extension_to_content_type.find(ext);
		if (find != extension_to_content_type.end())
			res.headers[http::header::CONTENT_TYPE] = find->second;
	}
}

/* Boyer-Moore */
template <typename T>
static void view_split(std::string_view s, std::string_view delim, T fn)
{
	if (s == delim)
		return;

	if (s.size() < delim.size()) {
		fn(s);
		return;
	}

	std::array<int, 256> table;
	for (auto &e : table)
		e = -1;

	for (size_t i = 0; i != delim.size(); i++)
		table[static_cast<unsigned char>(delim[i])] = delim.size()-i;

	size_t prev = 0;
	size_t i = delim.size()-1;

	auto find_next = [&](){
		for (;;) {
			const auto step = table[static_cast<unsigned char>(s[i])];
			i += step > 0 ? step : delim.size();
			if (i > s.size())
				return false;

			const auto maybe_delim = s.substr(i-delim.size(), delim.size());
			if (maybe_delim == delim)
				return true;
		}
	};

	while (find_next()) {
		if (i-prev < delim.size())
			continue;

		const auto body = s.substr(prev, i-prev-delim.size());
		fn(body);
		prev = i;
	}

	fn(s.substr(prev));
}

static void dirs_to_text(const std::vector<fs_entry> &v, std::string &s, std::string path)
{
	for (const auto &e : v) {
		if (e.type == DT_DIR) {
			std::string newpath;
			newpath.append(path)
				.append("/")
				.append(e.name);

			s.append(newpath)
				.append("/\n");

			dirs_to_text(e.files, s, std::move(newpath));
		} else {
			s.append(path)
				.append("/")
				.append(e.name)
				.append("\n");
		}
	}
}

static size_t find_http_eoh(std::string_view v)
{
	int seq = 0;

	for (size_t i = 0; i != v.size(); i++) {
		switch (v[i]) {
		default:
			seq = 0;
			continue;

		case '\r':
		case '\n':
			if (++seq == 4)
				return i+1;
		}
	}

	return 0;
}

/* timestamps look messy but filenames may lead to overriding
   simple workaround, but doesn't persist between restarts
*/
static std::atomic<size_t> next_file_idx;

static constexpr bool (*endpoints_post[])(const request &, response &) = {
	[](const request &req, response &res){
		if (req.query != "/upload")
			return false;

		res.body.append("POST request with ")
			.append(std::to_string(req.parts.size()))
			.append(" part(s)\n");

		for (auto v : req.parts)
			res.body.append("- ")
				.append(std::to_string(v.size()))
				.append(" bytes\n");

		for (auto v : req.parts) {
			auto idx = find_http_eoh(v);
			if (!idx) {
				res.body = "Bad request";
				res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
				res.status = http::status::_400_BAD_REQUEST;
				break;
			}

			std::unordered_map<http::header, std::string> part_headers;
			parser p{v.data()};
			if (!parse_http_headers(part_headers, p)) {
				res.body = "Could not parse multipart headers. Hint: Only ASCII chars supported\n";
				res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
				res.status = http::status::_400_BAD_REQUEST;
				return true;
			}

			const auto filebody = v.substr(idx);
			const auto num = next_file_idx.fetch_add(1, std::memory_order_relaxed);

			std::string filename;
			filename.append("static/upload/").append(std::to_string(num));

			auto find_part_content_type = part_headers.find(http::header::CONTENT_TYPE);
			if (find_part_content_type == part_headers.end()) {
				res.body = "No content type specified in multipart";
				res.headers[http::header::CONTENT_TYPE] = "tex/plain; charset=utf-8";
				res.status = http::status::_400_BAD_REQUEST;
				return true;
			}

			std::string_view content_type = find_part_content_type->second;
			const auto find_extension = content_type_to_extension.find(content_type);
			if (find_extension != content_type_to_extension.end()) {
				filename.append(".").append(find_extension->second);
			} else {
				res.body.clear();

				res.body.append("Unknown Content-Type '")
					.append(content_type)
					.append("'\n");

				res.status = http::status::_400_BAD_REQUEST;
				res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
				return true;
			}

			auto fd = std::fopen(filename.c_str(), "wb");
			if (!fd) {
				res.body.append("Could not open the file '")
					.append(filename)
					.append("' for writing");

				res.status = http::status::_500_INTERNAL_SERVER_ERROR;
				res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
				break;
			}

			std::fwrite(filebody.data(), 1, filebody.size(), fd);

			defer autoclose{[fd](){
				if (std::fclose(fd) < 0)
					std::fprintf(stderr, "warn: fclose errno=%d\n", errno);
			}};
		}

		res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
		return true;
	},
	[](const request &req, response &res){
		res.body.append("POST request to unknown endpoint: '")
			.append(req.query)
			.append("'");

		res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
		res.status = http::status::_404_NOT_FOUND;
		return true;
	}
};

static constexpr bool (*endpoints_get[])(const request &, response &) = {
	[](const request &req, response &res){
		size_t x, y;

		if (!parser{req.query.c_str()}("/add/", &x, "/", &y, parser::term{}))
			return false;

		res.body.append(std::to_string(x))
			.append("+")
			.append(std::to_string(y))
			.append("=")
			.append(std::to_string(x+y))
			.append("\n");

		res.headers[http::CONTENT_TYPE] = "text/plain; charset=utf-8";
		return true;
	},
	[](const request &req, response &res){
		if (req.query != "/list")
			return false;
		
		const auto files = read_dirs_sync("static/upload/");
		if (!files) {
			res.body = "Internal error";
			res.status = http::status::_500_INTERNAL_SERVER_ERROR;
			res.headers[http::CONTENT_TYPE] = "text/plain; charset=utf-8";
			return true;
		}
		
		res.body.append("<!DOCTYPE html><head><title>Files</title></head><body><table>")
			.append("<tr><th>Filename</th><th>Filesize</th></tr>");

		for (const auto &e : *files)
			res.body.append("<tr><td>")
				.append("<a href=\"/file/").append(e.name).append("\">")
				.append(e.name)
				.append("</a>")
				.append("</td><td>")
				.append(std::to_string(e.size))
				.append("</td></tr>");

		res.body.append("</table></body></html>");
		res.headers[http::header::CONTENT_TYPE] = "text/html; charset=utf-8";
		return true;
	},
	[](const request &req, response &res){
		if (req.query != "/dir")
			return false;

		auto files = read_dirs_sync("static/");
		if (!files) {
			res.body = "Internal error";
			res.status = http::status::_500_INTERNAL_SERVER_ERROR;
			res.headers[http::CONTENT_TYPE] = "text/plain; charset=utf-8";
			return true;
		}

		dirs_to_text(*files, res.body, "/file");
		res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
		return true;
	},
	[](const request &req, response &res){
		if (req.query != "/")
			return false;

		serve_static_file("static/index.html", res);
		return true;
	},
	[](const request &req, response &res){
		if (req.query != "/me")
			return false;

		res.body.append("You are ").append(req.peername);
		res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
		return true;
	},
	[](const request &req, response &res){
		parser::rest rest;
		if (!parser{req.query.c_str()}("/file/", &rest))
			return false;

		std::string filepath;
		filepath.append("static/upload/").append(rest.view);
		serve_static_file(std::move(filepath), res);
		return true;
	},
	[](const request &req, response &res){
		res.body.append("Could not GET ").append(req.query);
		res.status = http::status::_404_NOT_FOUND;
		res.headers[http::header::CONTENT_TYPE] = "text/plain; charset=utf-8";
		return true;
	}
};

[[maybe_unused]] static void xxd(const void *ptr, size_t sz)
{
	auto fd = popen("xxd", "w");
	if (!fd)
		return;

	defer autoclose{[fd](){
		if (pclose(fd) < 0)
			std::fprintf(stderr, "warn: pclose errno=%d\n", errno);
	}};

	std::fwrite(ptr, 1, sz, fd);
}

static bool serve_request(connection &con, std::string_view peername)
{
	size_t eoh = 0;

	for (;;) {
		eoh = find_http_eoh(std::string_view{con.rxbuf, con.rx});
		if (eoh)
			break;

		if (!con.receive())
			return false;
	}

	http::method method;
	parser::ascii_word query;
	http::protocol protocol;
	parser p{con.rxbuf};
	if (!p(&method, " ", &query, " ", &protocol, "\r\n"))
		return false;

	std::unordered_map<http::header, std::string> request_headers;
	if (!parse_http_headers(request_headers, p))
		return false;

	struct request req{
		std::string{query.view},
		request_headers,
		peername,
		{}
	};

	size_t request_size = eoh;

	auto find_content_length = request_headers.find(http::header::CONTENT_LENGTH);
	if (find_content_length != request_headers.end()) {
		size_t len;

		if (!parser{find_content_length->second.c_str()}(&len, parser::term{}))
			return false;

		request_size += len;
		while (con.rx < request_size)
			if (!con.receive())
				return false;
	}

	auto find_transfer_encoding = request_headers.find(http::header::TRANSFER_ENCODING);
	if (find_transfer_encoding != request_headers.end()) {
		std::fprintf(stderr, "todo: Transfer-Encoding\n");
		return false;
	}

	con.dump_request(request_size);

	auto find_content_type = request_headers.find(http::header::CONTENT_TYPE);
	if (find_content_type != request_headers.end()) {
		parser::rest rest;
		if (parser{find_content_type->second.c_str()}("multipart/form-data; boundary=", &rest)) {
			std::string boundary;
			boundary.append("--").append(rest.view);

			const auto body = std::string_view{con.rxbuf+eoh, request_size-eoh};
			std::vector<std::string_view> parts;
			view_split(body, boundary, [&](std::string_view v){
				if (v.size() <= 4)
					return;

				/* Leading and trailing \r\n */
				v = v.substr(2, v.size()-4);
				parts.push_back(v);
			});

			req.parts = std::move(parts);
		}
	}

	struct response res;
	res.headers[http::header::CONTENT_TYPE] = "application/octet-stream";
	res.headers[http::header::CONNECTION] = "Close";
	res.status = http::status::_200_OK;

	bool keepalive = false;
	auto find_connection = request_headers.find(http::header::CONNECTION);
	if (find_connection != request_headers.end()) {
		if (strcasecmp("Keep-Alive", find_connection->second.c_str()) == 0) {
			res.headers[http::header::CONNECTION] = "Keep-Alive";
			keepalive = true;
		}
	}

	switch (method) {
	default:
		std::fprintf(stderr, "fail: method %d not implemented\n", method);
		return false;

	case http::method::POST:
		for (auto fn : endpoints_post)
			if (fn(req, res))
				break;
		break;

	case http::method::GET:
		for (auto fn : endpoints_get)
			if (fn(req, res))
				break;
		break;
	}

	std::string response_headers_string;

	switch (protocol) {
	case http::protocol::HTTP1_0:
		response_headers_string.append("HTTP/1.0");
		break;

	case http::protocol::HTTP1_1:
		response_headers_string.append("HTTP/1.1");
		break;
	}

	response_headers_string.append(" ")
		.append(http::status_str[res.status])
		.append("\r\n");

	res.headers[http::header::CONTENT_LENGTH] = std::to_string(res.body.length());
	for (const auto &[k, v] : res.headers)
		response_headers_string.append(known_headers[k])
			.append(": ")
			.append(v)
			.append("\r\n");

	response_headers_string.append("\r\n");

	/* send headers */
	for (size_t tx = 0; tx != response_headers_string.length();) {
		auto lim = response_headers_string.length();
		auto n = send(con.fd, response_headers_string.c_str()+tx, lim-tx, MSG_NOSIGNAL);
		if (n < 0) {
			std::fprintf(stderr, "warn: send errno=%d\n", errno);
			return false;
		}
		tx += n;
	}

	/* send body */
	for (size_t tx = 0; tx != res.body.length();) {
		auto lim = res.body.length();
		auto n = send(con.fd, res.body.c_str()+tx, lim-tx, MSG_NOSIGNAL);
		if (n < 0) {
			std::fprintf(stderr, "warn: send errno=%d\n", errno);
			return false;
		}
		tx += n;
	}

	if (!keepalive)
		return false;

	con.discard(request_size);
	return true;
}

static void connection_handler(int fd, std::string peername)
{
	connection con{fd};

	defer autoclose{[fd](){
		if (close(fd) < 0)
			std::fprintf(stderr, "warn: close errno=%d\n", errno);
	}};

	while (serve_request(con, peername));
}

/* std::memcpy is the only way to typepun in C++ without UB */
static std::string get_peer_name(sockaddr *ptr)
{
	sockaddr_in6 addr6;
	sockaddr_in addr4;
	std::string ret;
	char buf[std::max(INET6_ADDRSTRLEN, INET_ADDRSTRLEN)];

	switch (ptr->sa_family) {
	case AF_INET:
		std::memcpy(&addr4, ptr, sizeof(addr4));
		inet_ntop(AF_INET, &addr4.sin_addr.s_addr, buf, sizeof(buf));
		return ret.append(buf)
			.append(std::to_string(ntohs(addr4.sin_port)));

	case AF_INET6:
		std::memcpy(&addr6, ptr, sizeof(addr6));
		inet_ntop(AF_INET6, &addr6.sin6_addr, buf, sizeof(buf));
		return ret.append("[")
			.append(buf)
			.append("]:")
			.append(std::to_string(ntohs(addr6.sin6_port)));
	}

	__builtin_unreachable();
}

int main()
{
	sockaddr_in6 addr{};
	addr.sin6_addr = IN6ADDR_ANY_INIT;
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(config::port);

	const int listenfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (listenfd < 0) {
		std::fprintf(stderr, "fail: socket errno=%d\n", errno);
		return 1;
	}

	defer autoclose{[listenfd](){
		if (close(listenfd) < 0)
			std::fprintf(stderr, "warn: close errno=%d\n", errno);
	}};

	int one = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
		std::fprintf(stderr, "fail: setsockopt errno=%d\n", errno);
		return 1;
	}

	int zero = 0;
	if (setsockopt(listenfd, SOL_IPV6, IPV6_V6ONLY, &zero, sizeof(zero)) < 0) {
		std::fprintf(stderr, "fail: setsockopt errno=%d\n", errno);
		return 1;
	}

	if (bind(listenfd, (sockaddr *) &addr, sizeof(addr)) < 0) {
		std::fprintf(stderr, "fail: bind errno=%d\n", errno);
		return 1;
	}

	if (listen(listenfd, 0) < 0) {
		std::fprintf(stderr, "fail: listen errno=%d\n", errno);
		return 1;
	}

	std::printf("Running :%d\n", config::port);

	for (;;) {
		static constexpr auto sockaddr_size_max = std::max(sizeof(sockaddr_in), sizeof(sockaddr_in6));
		static constexpr auto sockaddr_align_max = std::max(alignof(sockaddr_in), alignof(sockaddr_in6));
		alignas(sockaddr_align_max) char buf[sockaddr_size_max];
		socklen_t sz = sizeof(buf);

		const int clientfd = accept(listenfd, (sockaddr *) buf, &sz);
		if (clientfd < 0) {
			std::fprintf(stderr, "fail: accept errno=%d\n", errno);
			return 1;
		}

		std::thread{
			connection_handler,
			clientfd,
			get_peer_name((sockaddr *) buf)
		}.detach();
	}

	return 0;
}

/* TODO
  - get rid of <atomic> header
  - JSON
  - various cleanups/refactorings
  - ranges for videos
  - more error handling for disk operations
*/
