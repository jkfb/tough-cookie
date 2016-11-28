const path = require('path');

const config = {
  entry: path.resolve(__dirname, 'src/cookie.js'),
  output: {
    path: path.resolve(__dirname, 'lib'),
    filename: 'tough-cookie.js',
    library: 'tough-cookie',
    libraryTarget: 'umd',
    umdNamedDefine: true
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        include: [
          path.resolve(__dirname, 'src')
        ],
        use: [
          {
            loader: 'babel-loader',
            options: {
              presets: [ 'es2015' ]
            }
          }
        ]
      },
      {
        test: /\.(js|jsx)$/,
        include: [
          path.resolve(__dirname, 'src')
        ],
        enforce: 'pre',
        exclude: [
          path.resolve(__dirname, 'node_modules'),
          path.resolve(__dirname, 'test'),
          path.resolve(__dirname, 'lib')
        ],
        use: [
          {
            loader: 'eslint-loader'
          }
        ]
      }
    ]
  },
  devtool: 'source-map'
};

module.exports = config;
