import * as Http from 'http';
import * as Https from 'https';
import { Stream } from 'pump';

export type Options = {
  base?: string;
  cacheURLs?: number;
  requests?: {
    http?: Http.Agent;
    https?: Https.Agent;
  };
  keepAliveMsecs?: number;
  maxSockets?: number;
  rejectUnauthorized?: boolean;
};

export type ProxyRequestResponse = {
  statusCode: Number;
  headers: Http.OutgoingHttpHeaders;
  stream: Stream;
};

export type ProxyOptions = {
  base?: string;
  onClientConnectionTerminated?(res: Http.ServerResponse, err: Error, response: ProxyRequestResponse): void;
  onResponse?(req: Http.IncomingMessage, res: Http.ServerResponse, stream: Stream): void;
  rewriteRequestHeaders?(req: Http.IncomingMessage, headers: Http.IncomingHttpHeaders): Http.IncomingHttpHeaders;
  rewriteHeaders?(headers: Http.OutgoingHttpHeaders): Http.OutgoingHttpHeaders;
  request?: Http.RequestOptions;
  queryString?: string;
}

export type FastProxy = {
  proxy(
    originReq: Http.IncomingMessage,
    originRes: Http.ServerResponse,
    source: string,
    opts?: ProxyOptions
  ): void;
  close(): void;
}

declare function fastProxy(options?: Options): FastProxy

export default fastProxy
