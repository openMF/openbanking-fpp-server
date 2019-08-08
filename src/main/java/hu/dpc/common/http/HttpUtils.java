package hu.dpc.common.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

@ParametersAreNonnullByDefault
public class HttpUtils {

    private static final Log LOG = LogFactory.getLog(HttpUtils.class);

    /**
     * Split url query params
     *
     * @param url
     * @return
     * @throws UnsupportedEncodingException
     */
    @Nullable
    public static Map<String, String> splitQuery(final URL url) throws UnsupportedEncodingException {
        final String urlQuery = url.getQuery();
        if (null == urlQuery) {
            return null;
        }
        final String[] pairs = urlQuery.split("&");
        final Map<String, String> query_pairs = new LinkedHashMap<String, String>();
        for (final String pair : pairs) {
            final int idx = pair.indexOf('=');
            final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
            final String value =
                    idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
            query_pairs.put(key, value);
        }
        return query_pairs;
    }


    @NotNull
    public static <T extends HttpResponse> T doGET(final Class<T> type, final String query,
                                                   final Map<String, String> headers) throws ResponseStatusException {
        return call(HttpMethod.GET, type, query, headers, null);
    }

    @NotNull
    public static <T extends HttpResponse> T call(final HttpMethod method, final Class<T> type, final String query,
                                                  final Map<String, String> headers,
                                                  @org.jetbrains.annotations.Nullable final String body) throws ResponseStatusException {
        try {
            HttpResponse response = HttpHelper.doAPICall(method, new URL(query), headers, body);
            final ObjectMapper mapper = new ObjectMapper();
            final T result = mapper.readValue(response.getHttpRawContent(), type);
            result.setHttpResponseCode(response.getHttpResponseCode());
            result.setHttpRawContent(response.getHttpRawContent());

            return result;
        } catch (final Exception e) {
            LOG.error("Something went wrong!", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong!", e);
        }
    }
}
