import * as Http from 'http';
import * as Https from 'https';
import { Stream } from 'pump';

type Options = {
  base?: string;
  cacheURLs?: number;
  requests?: {
    http?: Http.Agent,
    https?: Https.Agent
  };
  keepAliveMsecs?: number;
  maxSockets?: number;
  rejectUnauthorized?: boolean;
}

type ProxyRequestResponse = {
  statusCode: Number;
  headers: Http.OutgoingHttpHeaders;
  stream: Stream;
}

declare function fastProxy(options?: Options): {
  proxy(
    originReq: Http.IncomingMessage,
    originRes: Http.ServerResponse,
    source: string,
    opts?: {
      base?: string;
      onClientConnectionTerminated?(res: Http.ServerResponse, err: Error, response: ProxyRequestResponse): void;
      onResponse?(req: Http.IncomingMessage, res: Http.ServerResponse, stream: Stream): void;
      rewriteRequestHeaders?(req: Http.IncomingMessage, headers: Http.IncomingHttpHeaders): Http.IncomingHttpHeaders;
      rewriteHeaders?(headers: Http.OutgoingHttpHeaders): Http.OutgoingHttpHeaders;
      request?: Http.RequestOptions;
      queryString?: string;
    }
  ): void;
  close(): void;
}

export default fastProxy
