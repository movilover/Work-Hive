// POST /api/postback — offerwall.ad webhook (HMAC verified)
import { route } from '../lib/owa.mjs';

export default {
  fetch(request) {
    return route('postback', request, process.env);
  },
};
