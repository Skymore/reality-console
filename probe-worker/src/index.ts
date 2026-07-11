import { connect } from "cloudflare:sockets";
import { handleRequest, type ProbeEnv, type TcpConnector } from "./handler";

export default {
  async fetch(request: Request, env: ProbeEnv): Promise<Response> {
    return handleRequest(request, env, connect as TcpConnector);
  },
} satisfies ExportedHandler<ProbeEnv>;
