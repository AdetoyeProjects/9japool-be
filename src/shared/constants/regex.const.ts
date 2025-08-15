const DEFAULT_MATCHERS = {
  base64: /data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+)/,
  email: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/,
};

export default DEFAULT_MATCHERS;
