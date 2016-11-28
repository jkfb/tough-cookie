'use strict';

const gulp = require('gulp');
const rename = require('gulp-rename');

gulp.task('default', () => gulp.src([ 'node_modules/punycode/punycode.es6.js' ])
  .pipe(rename({ dirname: 'third' }))
  .pipe(gulp.dest('src')));
