import * as Http from 'http';
import * as Http2 from 'http2';
import * as Https from 'https';

/**
 * HTTP client implementation, e.g: the `http`/`https` core modules or
 * `follow-redirects/http`/`follow-redirects/https`.
 */
export type RequestClient = {
  request(options: Https.RequestOptions, ...args: any[]): any;
};

/**
 * Besides the options described here, any option supported by the `http.Agent`
 * and `https.Agent` constructors is accepted (`maxFreeSockets`, `timeout`...).
 */
export type Options = Https.AgentOptions & {
  base?: string;
  cacheURLs?: number;
  requests?: {
    http?: RequestClient;
    https?: RequestClient;
  };
  keepAliveMsecs?: number;
  maxSockets?: number;
  rejectUnauthorized?: boolean;
};

export type ProxyRequest = Http.IncomingMessage | Http2.Http2ServerRequest;
export type ProxyResponse = Http.ServerResponse | Http2.Http2ServerResponse;

export type ProxyRequestResponse = {
  statusCode: number;
  headers: Http.IncomingHttpHeaders;
  stream: Http.IncomingMessage;
};

export type ProxyOptions = {
  base?: string;
  /**
   * Called when the client connection is terminated before the remote
   * response could be delivered. `response` is only defined if the remote
   * server responded, in such case its stream is destroyed after this callback
   * returns, unless it is being consumed.
   */
  onClientConnectionTerminated?(res: ProxyResponse, err: Error | null, response?: ProxyRequestResponse): void;
  onResponse?(req: ProxyRequest, res: ProxyResponse, stream: Http.IncomingMessage): void;
  rewriteRequestHeaders?(req: ProxyRequest, headers: Http.IncomingHttpHeaders): Http.IncomingHttpHeaders;
  rewriteHeaders?(headers: Http.OutgoingHttpHeaders): Http.OutgoingHttpHeaders;
  request?: Https.RequestOptions;
  queryString?: string | URLSearchParams | Record<string, any>;
}

export type FastProxy = {
  proxy(
    originReq: ProxyRequest,
    originRes: ProxyResponse,
    source?: string | null,
    opts?: ProxyOptions
  ): void;
  close(): void;
}

export declare function fastProxy(options?: Options): FastProxy

export default fastProxy
