// GET /api/offers — admin only: fetch offers from offerwall.ad
import { route } from '../lib/owa.mjs';

export default {
  fetch(request) {
    return route('offers', request, process.env);
  },
};
