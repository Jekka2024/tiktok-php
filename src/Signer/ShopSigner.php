<?php

namespace Jekka\Tiktok\Signer;

use Psr\Http\Message\RequestInterface;

/**
 * ShopSigner 类实现了 TikTok Shop API 的签名算法
 * 
 * 签名算法遵循以下步骤:
 * 1. 提取所有查询参数，除了 'sign', 'access_token', 'x-tts-access-token'
 * 2. 根据键名按字母顺序重新排序参数
 * 3. 将所有参数连接成格式为 {key}{value} 的字符串
 * 4. 在开头附加请求路径
 * 5. 如果请求头 content_type 不是 multipart/form-data，则在末尾附加请求体
 * 6. 用 app_secret 包装第5步中生成的字符串
 * 7. 使用 HMAC-SHA256 算法和密钥(secret)生成签名
 * 
 * @see https://partner.tiktokshop.com/doc/page/274638
 */
class ShopSigner implements SignerInterface
{
    /**
     * @var string 应用密钥，用于生成签名
     */
    protected $appSecret;

    /**
     * 构造函数初始化应用密钥
     * 
     * @param string $appSecret 应用密钥
     */
    public function __construct(string $appSecret)
    {
        $this->appSecret = $appSecret;
    }

    /**
     * TikTok Shop API 签名算法实现
     * 
     * @see https://partner.tiktokshop.com/doc/page/274638
     * @param RequestInterface $request PSR-7 请求对象
     * @param array $params 查询参数数组（引用传递）
     * @return RequestInterface 签名后的请求对象
     */
    public function sign(RequestInterface $request, array &$params): RequestInterface
    {
        // 1. Extract all query parameters except 'sign', 'access_token', 'x-tts-access-token'
        $paramsToBeSigned = $params;
        unset(
            $paramsToBeSigned['sign'],
            $paramsToBeSigned['access_token'],
            $paramsToBeSigned['x-tts-access-token']
        );

        // 2. Reorder parameters alphabetically by key name
        ksort($paramsToBeSigned);

        // 3.Concatenate all parameters into a string in the format {key}{value}
        $stringToBeSigned = '';
        foreach ($paramsToBeSigned as $k => $v) {
            if (!is_array($v)) {
                $stringToBeSigned .= $k . $v;
            }
        }

        // 4. Append request path at the beginning
        $stringToBeSigned =
            $request->getUri()->getPath()
            . $stringToBeSigned;

        // 5. If the request header content_type is not multipart/form-data, the request body is appended to the end
        if (
            $request->getMethod() !== 'GET'
            && stripos($request->getHeaderLine('content-type'), 'multipart/form-data') === false
        ) {
            $stringToBeSigned .= (string) $request->getBody();
        }

        // 6. Wrap the string generated in step 5 with app_secret
        $stringToBeSigned =
            $this->appSecret
            . $stringToBeSigned
            . $this->appSecret;

        // 7. Generate a signature using the HMAC-SHA256 algorithm and secret and add it to the parameters
        $params['sign'] = hash_hmac(
            'sha256',
            $stringToBeSigned,
            $this->appSecret
        );

        return $request;
    }
}