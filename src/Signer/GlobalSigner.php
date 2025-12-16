<?php

namespace Jekka\Tiktok\Signer;

use Psr\Http\Message\RequestInterface;

class GlobalSigner
{
    /**
     * @var string
     */
    protected $appSecret;

    public function __construct(string $appSecret)
    {
        $this->appSecret = $appSecret;
    }

    /**
     * Sign TikTok Shop Global API request
     *
     * @param RequestInterface $request
     * @param array $query
     * @param int $timestamp
     * @return RequestInterface
     */
    public function sign(RequestInterface $request, array $query, int $timestamp): RequestInterface
    {
        // 1. 修正 path（去掉 /global 前缀）
        $path = $request->getUri()->getPath();
        if (strpos($path, '/global/') === 0) {
            $path = substr($path, 7);
        }

        // 2. 处理 query（key + value 拼接）
        ksort($query);
        $queryString = '';
        foreach ($query as $k => $v) {
            if (!is_array($v)) {
                $queryString .= $k . $v;
            }
        }

        // 3. 拼 body（非 GET 且非 multipart）
        $body = '';
        if (
            $request->getMethod() !== 'GET'
            && stripos($request->getHeaderLine('content-type'), 'multipart/form-data') === false
        ) {
            $body = (string)$request->getBody();
        }

        // 4. 拼待签名字符串（timestamp 必须参与）
        $stringToSign =
            $this->appSecret
            . $path
            . $queryString
            . $body
            . $timestamp
            . $this->appSecret;

        // 5. 生成签名
        $signature = hash_hmac(
            'sha256',
            $stringToSign,
            $this->appSecret
        );

        // 6. 仅设置签名 header
        return $request->withHeader('x-tt-signature', $signature);
    }
}
