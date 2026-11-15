// GET /api/go — optional click bridge
import { route } from '../lib/owa.mjs';

export default {
  fetch(request) {
    return route('go', request, process.env);
  },
};
