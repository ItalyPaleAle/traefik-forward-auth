<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>{{ .Title }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="{{ .BaseUrl }}/style.css" nonce="{{ .CspNonce }}">
</head>

<style nonce="{{ .CspNonce }}">
@layer theme {
    :root {
        --bg-image-lg: url({{ .BackgroundLarge }});
        --bg-image-md: url({{ .BackgroundMedium }});
    }
}
</style>

<body>
    <div class="layout h-full">
        <div class="layout-container">
            <div class="layout-content">
                <div class="layout-content-main">
                    <h1 class="pb-2 text-2xl md:text-3xl md:pb-4">{{ .Title }}</h1>
                    <p class="w-full p-4 font-medium text-center bg-white rounded-lg dark:bg-gray-900">You're authenticated with provider <b><code>{{ .Provider }}</code></b> as <b><code>{{ .User }}</code></b>.</p>
                    <a href="{{ .LogoutUrl }}" class="p-0.5 text-sm font-medium rounded-lg group bg-linear-to-br red-to-yellow mt-2 md:mt-4">
                        <span class="relative text-xs md:text-sm w-full inline-flex items-center px-1.5 py-1 md:px-3 md:py-1.5 transition-all ease-in duration-75 bg-white dark:bg-gray-900 rounded-md group-hover:bg-transparent group-hover:dark:bg-transparent">
                            Log out
                        </span>
                    </a>
                </div>
                <div class="layout-content-side"></div>
            </div>
        </div>
    </div>
</body>

</html>
