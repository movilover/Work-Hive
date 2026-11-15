// GET /api/health — quick check
import { route } from '../lib/owa.mjs';

export default {
  fetch(request) {
    return route('health', request, process.env);
  },
};
