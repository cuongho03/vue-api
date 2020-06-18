# eslint-plugin-vue-storefront

ESLint rules for Vue Storefront

## Installation

You'll first need to install [ESLint](http://eslint.org):

```
$ npm i eslint --save-dev
```

Next, install `eslint-plugin-vue-storefront`:

```
$ npm install eslint-plugin-vue-storefront --save-dev
```

**Note:** If you installed ESLint globally (using the `-g` flag) then you must also install `eslint-plugin-vue-storefront` globally.

## Usage

Add `eslint-plugin-vue-storefront` to the plugins section of your `.eslintrc` configuration file. You can omit the `eslint-plugin-` prefix:

```json
{
    "plugins": [
        "vue-storefront"
    ]
}
```


Then configure the rules you want to use under the rules section.

```json
{
    "rules": {
        "vue-storefront/no-corecomponent-import": "error",
        "vue-storefront/no-corecomponent": "error",
        "vue-storefront/no-corepage-import": "error",
        "vue-storefront/no-corepage": "error"
    }
}
```

## Supported Rules

* no-corecomponent-import
* no-corecomponent
* no-corepage-import
* no-corepage




